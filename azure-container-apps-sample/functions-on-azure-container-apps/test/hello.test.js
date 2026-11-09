const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const { hello } = require('../src/hello');

const root = path.join(__dirname, '..');
const read = (file) => readFileSync(path.join(root, file), 'utf8');
const template = JSON.parse(read('main.json'));
const app = template.resources[0];

test('hello returns the documented JSON response with HTTP 200', async () => {
    assert.deepEqual(await hello(), {
        status: 200,
        headers: { 'Content-Type': 'application/json; charset=utf-8' },
        jsonBody: { message: 'Hello, world!' }
    });
});

test('response does not echo caller input or leak mutable state across requests', async () => {
    const first = await hello({ body: 'private input' });
    first.jsonBody.message = 'changed';
    assert.deepEqual((await hello()).jsonBody, { message: 'Hello, world!' });
});

test('Functions v4 registers an anonymous GET at /api/hello', () => {
    let registration;
    vm.runInNewContext(read('src/functions/hello.js'), {
        require(name) {
            if (name === '@azure/functions') {
                return { app: { http: (name, options) => { registration = { name, options }; } } };
            }
            assert.equal(name, '../hello');
            return { hello };
        }
    });
    assert.equal(registration.name, 'hello');
    assert.equal(registration.options.route, 'hello');
    assert.equal(registration.options.authLevel, 'anonymous');
    assert.equal(Array.from(registration.options.methods).join(','), 'GET');
    assert.equal(registration.options.handler, hello);
    assert.equal(JSON.parse(read('host.json')).extensions.http.routePrefix, 'api');
    assert.equal(JSON.parse(read('package.json')).main, 'src/functions/hello.js');
});

test('ARM uses native Functions integration and explicit workload binding', () => {
    assert.equal(template.resources.length, 1);
    assert.equal(app.type, 'Microsoft.App/containerApps');
    assert.equal(app.kind, 'functionapp');
    assert.equal(app.properties.environmentId, "[parameters('environmentId')]");
    assert.equal(app.properties.workloadProfileName, "[parameters('workloadProfileName')]");
    assert.deepEqual(template.parameters.location.allowedValues, ['uaenorth']);
    assert.equal(template.parameters.workloadProfileName.defaultValue, 'confidential');
});

test('ARM requires HTTPS, port 80, ready traffic and bounded replica count', () => {
    assert.equal(app.properties.configuration.ingress.allowInsecure, false);
    assert.equal(app.properties.configuration.ingress.targetPort, 80);
    assert.deepEqual(app.properties.configuration.ingress.traffic, [{ latestRevision: true, weight: 100 }]);
    assert.deepEqual(app.properties.template.scale, { minReplicas: 1, maxReplicas: 1 });
    assert.match(template.outputs.helloUrl.value, /https:\/\/.*\/api\/hello/);
});

test('ACR pulls and host storage use a user-assigned managed identity, not keys', () => {
    assert.equal(app.identity.type, 'UserAssigned');
    assert.equal(app.properties.configuration.registries[0].identity, "[parameters('identityId')]");
    const settings = Object.fromEntries(app.properties.template.containers[0].env.map(({ name, value }) => [name, value]));
    assert.equal(settings.AzureWebJobsStorage__credential, 'managedidentity');
    assert.equal(settings.AzureWebJobsStorage__clientId, "[parameters('identityClientId')]");
    assert.equal(settings.AzureWebJobsStorage__accountName, "[parameters('storageAccountName')]");
    assert.equal(settings.AzureWebJobsStorage, undefined);
    assert.equal(app.properties.configuration.secrets, undefined);
});

test('container uses the Functions runtime, locked production dependencies, and excludes local settings', () => {
    const dockerfile = read('Dockerfile');
    assert.match(dockerfile, /FROM mcr\.microsoft\.com\/azure-functions\/node:4-node24/);
    assert.equal(JSON.parse(read('package.json')).engines.node, '>=24 <25');
    assert.match(dockerfile, /npm ci --omit=dev/);
    assert.match(dockerfile, /RUN node --version && npm ci/);
    assert.match(dockerfile, /COPY src \.\/src/);
    assert.match(dockerfile, /EXPOSE 80/);
    assert.doesNotMatch(dockerfile, /COPY \. /);
    assert.match(read('.dockerignore'), /local\.settings\*\.json/);
    assert.match(read('.gitignore'), /local\.settings\.json/);
});

test('deployment instructions require a fresh base image and describe runtime upgrade boundaries', () => {
    const readme = read('README.md');
    assert.match(readme, /docker build --pull --no-cache/);
    assert.match(readme, /az acr run .*--file acr-task\.yaml/);
    const task = read('acr-task.yaml');
    assert.match(task, /--pull --no-cache/);
    assert.match(task, /functions-hello:\{\{\.Run\.ID\}\}/);
    assert.match(task, /- push:/);
    assert.match(readme, /before \*\*every deployment\*\*/);
    assert.match(readme, /Running containers \*\*do not update themselves\*\*/);
});

test('local development uses the storage emulator, never a cloud connection string', () => {
    const settings = JSON.parse(read('local.settings.example.json')).Values;
    assert.equal(settings.AzureWebJobsStorage, 'UseDevelopmentStorage=true');
    assert.match(JSON.parse(read('package.json')).scripts.storage, /^azurite /);
    assert.match(read('.gitignore'), /\.azurite/);
    assert.match(read('.dockerignore'), /\.azurite/);
});

test('private host storage uses a separate subnet and VNet-linked blob DNS', () => {
    const network = JSON.parse(read('host-storage-network.json'));
    assert.equal(network.resources.length, 5);
    const subnet = network.resources.find(({ type }) => type === 'Microsoft.Network/virtualNetworks/subnets');
    assert.equal(network.parameters.subnetPrefix.defaultValue, '10.42.2.0/24');
    assert.equal(subnet.properties.privateEndpointNetworkPolicies, 'Disabled');
    assert.equal(subnet.properties.delegations, undefined);
    assert.equal(network.resources.some(({ type }) => type === 'Microsoft.Network/virtualNetworks'), false);
    const endpoint = network.resources.find(({ type }) => type === 'Microsoft.Network/privateEndpoints');
    const connection = endpoint.properties.privateLinkServiceConnections[0].properties;
    assert.deepEqual(connection.groupIds, ['blob']);
    assert.equal(connection.privateLinkServiceId, "[parameters('storageAccountId')]");
    assert.equal(network.variables.zoneName, 'privatelink.blob.core.windows.net');
    const link = network.resources.find(({ type }) => type === 'Microsoft.Network/privateDnsZones/virtualNetworkLinks');
    assert.equal(link.properties.registrationEnabled, false);
    assert.equal(link.properties.virtualNetwork.id, "[resourceId('Microsoft.Network/virtualNetworks', parameters('vnetName'))]");
    const group = network.resources.find(({ type }) => type === 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups');
    assert.equal(group.properties.privateDnsZoneConfigs[0].properties.privateDnsZoneId,
        "[resourceId('Microsoft.Network/privateDnsZones', variables('zoneName'))]");
    assert.match(read('README.md'), /--public-network-access Disabled/);
});
