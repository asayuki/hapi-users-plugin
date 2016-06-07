# Changelog

## 2016-06-07

* You will now be asked to create a user when starting application if there are no users.

## 2016-06-06

* Changes to extra_fields
    * Removed `extra_fields`
    * Added `create_extra_fields` instead for user object creation
    * Added `update_extra_fields` for user object update so the validation can be different.
* Removed console.log
* Moved validation higher up in routes for easier view what payload might be or not.
