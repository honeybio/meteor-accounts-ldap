Package.describe({
  'summary': 'Meteor account login via LDAP using activedirectory.js',
  'version': '0.1.4',
  'git' : 'git://git.bespintech.com/meteor-accounts-ldap',
  'name' : 'bespintech:meteor-accounts-ldap'
});

Npm.depends({'activedirectory' : '0.7.0'});

Package.on_use(function (api) {
  // api.use(['coffeescript@1.0.10'], 'server');
  api.use(['accounts-base@1.2.1'], ['client', 'server']);
  api.imply('accounts-base@1.2.1', ['client', 'server']);
  api.use(['templating@1.1.4','jquery@1.11.4'], 'client');
  api.add_files([
    'ldap_client.html',
    'ldap_client.js'], 'client');
  api.add_files('ldap_server.js', 'server');
});
