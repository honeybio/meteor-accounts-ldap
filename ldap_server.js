var ActiveDirectory, Future, UserQuery, assert;

ActiveDirectory = Npm.require('activedirectory');

Future = Npm.require('fibers/future');

assert = Npm.require('assert');

UserQuery = (function() {
  function UserQuery(username) {
    this.ad = ActiveDirectory({
      url: Meteor.settings.ldap.url,
      baseDN: Meteor.settings.ldap.baseDn,
      username: Meteor.settings.ldap.bindCn,
      password: Meteor.settings.ldap.bindPassword,
      attributes: {
        user: ["dn"].concat(Meteor.settings.ldap.autopublishFields)
      }
    });
    this.username = this.sanitize_for_search(username);
  }

  UserQuery.prototype.sanitize_for_search = function(s) {
    s = s.replace('\\', '\\5C');
    s = s.replace('\0', '\\00');
    s = s.replace('*', '\\2A');
    s = s.replace('(', '\\28');
    s = s.replace(')', '\\29');
    return s;
  };

  UserQuery.prototype.findUser = function() {
    var userFuture, userObj, username;
    userFuture = new Future;
    username = this.username;
    this.ad.findUser(this.username, function(err, userObj) {
      if (err) {
        if (Meteor.settings.ldap.debug) {
          console.log('ERROR: ' + JSON.stringify(err));
        }
        userFuture["return"](false);
        return;
      }
      if (!userObj) {
        if (Meteor.settings.ldap.debug) {
          console.log('User: ' + username + ' not found.');
        }
        return userFuture["return"](false);
      } else {
        if (Meteor.settings.ldap.debug) {
          console.log(JSON.stringify(userObj));
        }
        return userFuture["return"](userObj);
      }
    });
    userObj = userFuture.wait();
    if (!userObj) {
      throw new Meteor.Error(403, 'Invalid username');
    }
    return this.userObj = userObj;
  };

  UserQuery.prototype.authenticate = function(password) {
    var authenticateFuture, success;
    authenticateFuture = new Future;
    this.ad.authenticate(this.userObj.dn, password, function(err, auth) {
      if (err) {
        if (Meteor.settings.ldap.debug) {
          console.log('ERROR: ' + JSON.stringify(err));
        }
        authenticateFuture["return"](false);
        return;
      }
      if (auth) {
        if (Meteor.settings.ldap.debug) {
          console.log('Authenticated!');
        }
        authenticateFuture["return"](true);
      } else {
        if (Meteor.settings.ldap.debug) {
          console.log('Authentication failed!');
        }
        authenticateFuture["return"](false);
      }
    });
    success = authenticateFuture.wait();
    if (!success || password === '') {
      throw new Meteor.Error(403, 'Invalid credentials');
    }
    this.autenticated = success;
    return success;
  };

  UserQuery.prototype.getGroupMembershipForUser = function() {
    var groupsFuture;
    groupsFuture = new Future;
    this.ad.getGroupMembershipForUser(this.userObj.dn, function(err, groups) {
      if (err) {
        console.log('ERROR: ' + JSON.stringify(err));
        groupsFuture["return"](false);
        return;
      }
      if (!groups) {
        console.log('User: ' + this.userObj.dn + ' not found.');
        groupsFuture["return"](false);
      } else {
        console.log(JSON.stringify(groups))
        if (Meteor.settings.ldap.debug) {
          console.log('Groups found for ' + this.userObj.dn + ': ' + JSON.stringify(groups));
        }
        groupsFuture["return"](groups);
      }
    });
    return groupsFuture.wait();
  };

  UserQuery.prototype.isUserMemberOf = function(groupName) {
    var isMemberFuture;
    isMemberFuture = new Future;
    this.ad.isUserMemberOf(this.userObj.dn, groupName, function(err, isMember) {
      if (err) {
        console.log('ERROR: ' + JSON.stringify(err));
        isMemberFuture["return"](false);
        return;
      }
      if (Meteor.settings.ldap.debug) {
        console.log(this.userObj.displayName + ' isMemberOf ' + groupName + ': ' + isMember);
      }
      isMemberFuture["return"](isMember);
    });
    return isMemberFuture.wait();
  };

  UserQuery.prototype.queryMembershipAndAddToMeteor = function(callback) {
    var ad, groupName, i, len, ref, results, userObj;
    ref = Meteor.settings.ldap.groupMembership;
    results = [];
    for (i = 0, len = ref.length; i < len; i++) {
      groupName = ref[i];
      ad = this.ad;
      userObj = this.userObj;
      results.push((function(groupName) {
        return ad.isUserMemberOf(userObj.dn, groupName, function(err, isMember) {
          return (function(groupName) {
            if (err) {
              if (Meteor.settings.ldap.debug) {
                return console.log('ERROR: ' + JSON.stringify(err));
              }
            } else {
              if (Meteor.settings.ldap.debug) {
                console.log(userObj.dn + ' isMemberOf ' + groupName + ': ' + isMember);
              }
              return callback(groupName, isMember);
            }
          })(groupName);
        });
      })(groupName));
    }
    return results;
  };

  return UserQuery;

})();

Accounts.registerLoginHandler('ldap', function(request) {
  var authenticated, hashStampedToken, stampedToken, user, userId, userObj, user_query;
  if (!request.ldap) {
    return void 0;
  }
  user_query = new UserQuery(request.username);
  if (Meteor.settings.ldap.debug) {
    console.log('LDAP authentication for ' + request.username);
  }
  user_query.findUser();
  authenticated = user_query.authenticate(request.pass);
  if (Meteor.settings.ldap.debug) {
    console.log('* AUTHENTICATED:', authenticated);
  }
  userId = void 0;
  userObj = user_query.userObj;
  userObj.username = request.username;
  user = Meteor.users.findOne({
    dn: userObj.dn
  });
  if (user) {
    userId = user._id;
    Meteor.users.update(userId, {
      $set: userObj
    });
  } else {
    userId = Meteor.users.insert(userObj);
  }
  if (Meteor.settings.ldap.autopublishFields) {
    Accounts.addAutopublishFields({
      forLoggedInUser: Meteor.settings.ldap.autopublishFields,
      forOtherUsers: Meteor.settings.ldap.autopublishFields
    });
  }
  stampedToken = Accounts._generateStampedLoginToken();
  hashStampedToken = Accounts._hashStampedToken(stampedToken);
  Meteor.users.update(userId, {
    $push: {
      'services.resume.loginTokens': hashStampedToken
    }
  });
  user_query.queryMembershipAndAddToMeteor(Meteor.bindEnvironment(function(groupName, isMember) {
    if (isMember) {
      Meteor.users.update(userId, {
        $addToSet: {
          'memberOf': groupName
        }
      });
      return Meteor.users.update(userId, {
        $pull: {
          'notMemberOf': groupName
        }
      });
    } else {
      Meteor.users.update(userId, {
        $pull: {
          'memberOf': groupName
        }
      });
      return Meteor.users.update(userId, {
        $addToSet: {
          'notMemberOf': groupName
        }
      });
    }
  }));
  return {
    userId: userId,
    token: stampedToken.token,
    tokenExpires: Accounts._tokenExpiration(hashStampedToken.when)
  };
});
