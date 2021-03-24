const axios = require("axios");

class ChainClient {

    query_task(req) {
        return axios.post(ChainClient.url + '/query_task', req);
    }

    query_signature(req) {
        return axios.post(ChainClient.url + '/query_signature', req);
    }
}

ChainClient.url = 'localhost:9999';

module.exports = ChainClient;