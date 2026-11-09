const { app } = require('@azure/functions');
const { hello } = require('../hello');

app.http('hello', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'hello',
    handler: hello
});
