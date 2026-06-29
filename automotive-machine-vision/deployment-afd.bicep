param location string = resourceGroup().location
param frontDoorName string = 'amv-afd-${uniqueString(resourceGroup().id)}'
param aciOriginFqdn string
param originHostHeader string = aciOriginFqdn

var profileName = frontDoorName
var endpointName = 'amv-endpoint-${uniqueString(resourceGroup().id)}'
var originGroupName = 'amv-origin-group'
var originName = 'amv-aci-origin'
var routeName = 'amv-route'

resource frontDoor 'Microsoft.Cdn/profiles@2024-02-01' = {
  name: profileName
  location: 'global'
  sku: {
    name: 'Standard_AzureFrontDoor'
  }
  properties: {}
}

resource originGroup 'Microsoft.Cdn/profiles/originGroups@2024-02-01' = {
  parent: frontDoor
  name: originGroupName
  properties: {
    loadBalancingSettings: {
      sampleSize: 4
      successfulSamplesRequired: 3
      additionalLatencyInMilliseconds: 50
    }
    healthProbeSettings: {
      probePath: '/'
      probeRequestType: 'GET'
      probeProtocol: 'Http'
      probeIntervalInSeconds: 100
    }
    sessionAffinityState: 'Disabled'
  }
}

resource origin 'Microsoft.Cdn/profiles/originGroups/origins@2024-02-01' = {
  parent: originGroup
  name: originName
  properties: {
    hostName: aciOriginFqdn
    httpPort: 80
    httpsPort: 443
    originHostHeader: originHostHeader
    priority: 1
    weight: 1000
    enabledState: 'Enabled'
  }
}

resource endpoint 'Microsoft.Cdn/profiles/afdEndpoints@2024-02-01' = {
  parent: frontDoor
  name: endpointName
  location: 'global'
  properties: {
    enabledState: 'Enabled'
  }
}

resource route 'Microsoft.Cdn/profiles/afdEndpoints/routes@2024-02-01' = {
  parent: endpoint
  name: routeName
  properties: {
    customDomains: []
    originGroup: {
      id: originGroup.id
    }
    ruleSets: []
    supportedProtocols: [
      'Https'
      'Http'
    ]
    patternsToMatch: [
      '/*'
    ]
    forwardingProtocol: 'HttpOnly'
    linkToDefaultDomain: 'Enabled'
    httpsRedirect: 'Enabled'
  }
  dependsOn: [
    origin
  ]
}

output frontDoorEndpoint string = endpoint.properties.hostName
output frontDoorId string = frontDoor.id
output frontDoorName string = frontDoor.name
