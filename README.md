# wordpress-magic-link

*This should be considered an early alpha and not be deployed to a production site or sites without extra security*

A simple WordPress plugin that allows a user to request a "magic link" to login to a WordPress site with just their email address or username. 

This plugin is very sparse with feedback if there is an error or something doesn't match -- to help keep it obtuse and keep hackers guessing.

Set the defaults at the top of the plugin code:

```
define("PB_MAGIC_LINK_VALID_MINUTES", 60);
define("PB_MAGIC_LINK_LENGTH", 16); //actual code length will be ~3x this number
define("PB_MAGIC_LINK_LOGIN_URL", wp_login_url());
define("PB_MAGIC_LINK_SUCCESS_URL", get_site_url()."/user/");
```

TO USE: add [request_magic_link] shortcode to a page where the user can request the magic link. Will display and process a form to allows the request.

2019-06-27 - early alpha release - first public release
2020-02-11 - updated login process, removed the references to particular sites, removed internal logging calls