import requests


class MANDIANT():
    def __init__(self):
        self.elastic_url = 'https://elastic:6Ls8i254pGcbr5FaPH0K@10.34.12.45:9200/logs-*/_search'

    def get_mandiant_ioc_information(self):
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": "now-1d"
                                }
                            }
                        }
                    ],
                    "must": [
                        {
                            "match": {
                                "data_stream.dataset": "ti_mandiant_advantage.threat_intelligence"
                            }
                        },
                        {
                            "match": {
                                "threat.indicator.type": "ipv4-addr"
                            }
                        },
                        {
                            "range": {
                                "threat.indicator.last_seen": {
                                    "gte": "now-30d"
                                }
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "UniqueIP": {
                    "terms": {
                        "field": "threat.indicator.ip",
                        "size": 10000
                    },
                    "aggs": {
                        "ThreatConfidence": {
                            "terms": {
                                "field": "mandiant.threat_intelligence.ioc.mscore",
                                "size": 1
                            }
                        },
                        "LastSeen": {
                            "terms": {
                                "field": "threat.indicator.last_seen",
                                "size": 1
                            }
                        },
                        "Actors": {
                          "terms": {
                            "field": "mandiant.threat_intelligence.ioc.attributed_associations.name",
                            "size": 1
                          }
                        }
                    }
                }
            }
        }

        # Run query
        response = requests.get(url=self.elastic_url, json=query, verify=False, timeout=300)
        return response.json()['aggregations']['UniqueIP']['buckets']


class SIEM():
    def __init__(self):
        self.elastic_url = 'https://elastic:zR60oSfYTQwuprHkyGao@10.34.9.202:9200/firewall/_search'

    def get_last_seen(self, ip:str):
        query = {
            "size": 1,
            "query": {
                "bool": {
                    "minimum_should_match": 1,
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": "now-2d"
                                }
                            }
                        }
                    ],
                    "must": [
                        {
                            "match": {
                                "source.ip": f"{ip}"
                            }
                        }
                    ],
                    "should": [
                        {
                            "match": {
                                "event.outcome": "built"
                            }
                        },
                        {
                            "match": {
                                "event.outcome": "teardown"
                            }
                        }
                    ]
                }
            },
            "sort": [
                {
                "@timestamp": {
                    "order": "desc"
                }
                }
            ],
            "_source": [ "@timestamp"]
        }
        try:
            # Run query
            response = requests.get(url=self.elastic_url, json=query, verify=False, timeout=300)
            return response.json()['hits']['hits'][0]['@timestamp']
        except:
            return None

    def get_network_connection_information(self, ip:str):
        query = {
            "query": {
                "bool": {
                    "minimum_should_match": 1,
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": "now-1d"
                                }
                            }
                        }
                    ],
                    "must": [
                        {
                            "match": {
                                "source.ip": f"{ip}"
                            }
                        }
                    ],
                    "should": [
                        {
                            "match": {
                                "event.outcome": "teardown"
                            }
                        }
                    ],
                    "must_not": [
                        {
                            "match": {
                                "network.bytes": 0
                            }
                        }
                    ]
                }
            }
        }
        try:
            # Run query
            response = requests.get(url=self.elastic_url, json=query, verify=False, timeout=300)
            return response.json()['count']
        except:
            return None

