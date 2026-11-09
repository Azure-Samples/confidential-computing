async function hello() {
    return {
        status: 200,
        headers: { 'Content-Type': 'application/json; charset=utf-8' },
        jsonBody: { message: 'Hello, world!' }
    };
}

module.exports = { hello };
