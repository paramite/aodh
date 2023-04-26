#
# Copyright 2023 Red Hat, Inc
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import requests

from oslo_config import cfg
from oslo_log import log

from aodh.evaluator import threshold


LOG = log.getLogger(__name__)
OPTS = [
    cfg.StrOpt('prometheus_host',
               default='127.0.0.1',
               help='The host where Prometheus API instance is running.'),
    cfg.IntOpt('prometheus_port',
               default=9090,
               help='The port on which Prometheus API instance'
                    ' is listening.'),
    cfg.StrOpt('prometheus_ca_cert',
               help='Path to TLS CA cert file for Prometheus host'
                    ' verification.'),
    cfg.StrOpt('prometheus_client_cert',
               help='Path to TLS cert file for Prometheus client'
                    ' verification.'),
    cfg.StrOpt('prometheus_client_key',
               help='Path to TLS key file for Prometheus client'
                    ' verification.'),
    cfg.StrOpt('prometheus_user',
               help='Username for HTTP basic authententication'
                    ' on Prometheus API instance.'),
    cfg.StrOpt('prometheus_password',
               secret=True,
               help='Password for HTTP basic authententication'
                    ' on Prometheus API instance.'),
]


class PrometheusAPIClientError(Exception):
    def __init__(self, response):
        self.resp = response

    def __repr__(self) -> str:
        if self.resp.status_code != requests.codes.ok:
            return f'[{self.resp.status_code}] {self.resp.reason}'
        else:
            decoded = self.resp.json()
            return f'[{decoded.status}]'


class PrometheusMetric:
    def __init__(self, input):
        self.timestamp = input['value'][0]
        self.labels = input['metric']
        self.value = input['value'][1]

    def __repr__(self) -> str:
        return "%s %f" % (
            ["%s=%s" % (k, v) for k, v in self.labels.items()],
            self.value
        )


class PrometheusRBAC:
    # TODO(mmagr): this class will be responsible for attaching Keystone
    #              tenant info to prometheus queries
    def __init__(self, rbac):
        """TODO(mmagr)"""

    def enrich_query(self, query):
        # TODO(mmagr)
        return query


class PrometheusAPIClient:
    def __init__(self, host, rbac=None):
        self._host = host
        self._rbac = PrometheusRBAC(rbac)
        self._session = requests.Session()
        self._session.verify = False

    def set_ca_cert(self, ca_cert):
        self._session.verify = ca_cert

    def set_client_cert(self, client_cert, client_key):
        self._session.cert = client_cert
        self._session.key = client_key

    def set_basic_auth(self, auth_user, auth_password):
        self._session.auth = (auth_user, auth_password)

    def get(self, query):
        url = (f"{'https' if self._session.verify else 'http'}://"
               f"{self._host}/api/v1/query")
        q = self._rbac.enrich_query(query)
        resp = self._session.get(url, params=dict(query=q),
                                 headers={'Accept': 'application/json'})
        if resp.status_code != requests.codes.ok:
            raise PrometheusAPIClientError(resp)
        decoded = resp.json()
        if decoded['status'] != 'success':
            raise PrometheusAPIClientError(resp)

        if decoded['data']['resultType'] == 'vector':
            result = [PrometheusMetric(i) for i in decoded['data']['result']]
        else:
            result = [PrometheusMetric(decoded)]
        return result


class PrometheusBase(threshold.ThresholdEvaluator):
    def __init__(self, conf):
        super(PrometheusBase, self).__init__(conf)
        php = f'{conf.prometheus_host}:{conf.prometheus_port}'
        self._promclient = PrometheusAPIClient(php)
        if conf.prometheus_ca_cert:
            self._promclient.set_ca_cert(conf.prometheus_ca_cert)
        if conf.prometheus_client_cert and conf.prometheus_client_key:
            self._promclient.set_client_cert(conf.prometheus_client_cert,
                                             conf.prometheus_client_key)
        if conf.prometheus_user and conf.prometheus_password:
            self._promclient.set_basic_auth(conf.prometheus_user,
                                            conf.prometheus_password)

    def _get_metric_data(self, query):
        LOG.debug(f'Querying Prometheus instance on: {query}')
        return self._promclient.get(query)


class PrometheusEvaluator(PrometheusBase):

    def _sanitize(self, metric_data):
        sanitized = [float(m.value) for m in metric_data]
        LOG.debug(f'Sanited Prometheus metric data: {metric_data}'
                  f' to statistics: {sanitized}')
        return sanitized

    def evaluate_rule(self, alarm_rule):
        """Evaluate alarm rule.

        :returns: state, trending state, statistics and two irrelevant values
        """
        metrics = self._get_metric_data(alarm_rule['query'])
        statistics = self._sanitize(metrics)
        if not statistics:
            raise threshold.InsufficientDataError('datapoints are unknown')

        return self._process_statistics(alarm_rule, statistics)

    def _unknown_reason_data(self, alarm, statistics):
        LOG.warning(f'Transfering alarm {alarm} on unknown reason')
        last = None if not statistics else statistics[-1]
        return self._reason_data('unknown', len(statistics), last)
