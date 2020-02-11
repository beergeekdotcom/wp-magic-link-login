<?php
/*
Plugin Name: Wordpress Magic Link Login
Plugin URI: https://beergeek.com
Description: A simple way for a user to login, if they forgot their password
Version: 0.1.0
Author: Jeff Scott
Author URI: http://beergeek.com
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html
Inspired by: One Time Login - https://wordpress.org/plugins/one-time-login/ by Daniel Bachhuber

This plugin is very sparse with feedback if there is an error or something doesn't match -- to help keep it obtuse and keep hackers guessing.

TO USE: add [request_magic_link] shortcode to a page where the user can request the magic link. Will display and process a form to allow the request.

//REF: https://wordpress.org/plugins/one-time-login/
//REF: https://security.stackexchange.com/questions/129846/implementing-an-autologin-link-in-an-email
//REF: https://www.php.net/manual/en/function.openssl-random-pseudo-bytes.php

//TODO: admin > settings page for details and setting of the defaults
//TODO: install / uninstall function to setup the defaults
//TODO: login page and logout page for magic link
//TODO: perhaps OO this puppy
//TODO: routine to hook into the wordfence too many logins trap
*/

//Set defaults here
define("PB_MAGIC_LINK_VALID_MINUTES", 60);
define("PB_MAGIC_LINK_LENGTH", 16); //actual code length will be ~3x this number
define("PB_MAGIC_LINK_LOGIN_URL", wp_login_url());
define("PB_MAGIC_LINK_SUCCESS_URL", get_site_url()."/user/");

function pb_generate_magic_link_code($uid, $email) {

  $makeminesalty = md5(openssl_random_pseudo_bytes(PB_MAGIC_LINK_LENGTH, $cs).time().wp_generate_password( PB_MAGIC_LINK_LENGTH, true, true ));
  
  $enc = $uid."::".$makeminesalty."::".crypt($uid.$email);

  return base64url_encode($enc);
}

function pb_make_and_save_magic_link($uid, $email) {

  if (!empty($uid) && !empty($email)) {
    //is a valid user and does email match?
    $user = get_user_by("ID", $uid);
    if ($user->ID == $uid && $user->user_email == $email) {

      //Is there already a valid code?
      $current_code = get_user_meta( $uid, "magic_link", true );

      //If there already exists a code and it's still valid, return it
      if ($current_code && is_array($current_code) && $current_code['code'] && $current_code['time']) {
        if (((int)$current_code['time'] + ((int)PB_MAGIC_LINK_VALID_MINUTES * 60)) > time()) {
          // still valid -- don't reset
          return $current_code;
        }
      }

      //Create a new code and save to user meta  
      if($magic_link_code = pb_generate_magic_link_code($uid, $email)) {
        $magic_link_data = array("code" => $magic_link_code, "time" => time());
        update_user_meta( $uid, "magic_link", $magic_link_data );
        return $magic_link_data;
      }
    }
  }

  return false;
}

// Go through a series of checks to make sure the login code is valid
function pb_verify_magic_link_code($login_code) {
  
  $parts = explode("::", base64url_decode($login_code));

  //verify the user
  if (!$user = get_user_by("ID", $parts[0])) {
    return false;
  }

  //Make sure user isn't an editor or higher user
  if (user_can($user, "administrator") || user_can($user, "editor")) {
    return false;
  }

  //Grab the code for the user and verify it
  $current_code = get_user_meta( $parts[0], "magic_link", true );

  //is valid data?
  if (!$current_code || !is_array($current_code) || !$current_code['code'] || !$current_code['time']) {
    return false;
  }

  //Has it expired
  if ($current_code['time'] < (time() - (PB_MAGIC_LINK_VALID_MINUTES * 60))) {
    return false;
  }

  //is the code the same
  if ($current_code['code'] <> $login_code) {
    return false;
  }

  //verify the crypt too
  if (hash_equals($parts[2], crypt($parts[0].$user->user_email, $parts[2]))) {
    return $user;
  }

  //if we fall out
  return false;

}

// Send the email with the magic login link
// user - WP user object
// mlink - array("time" => creation time, "code" => Link to login)
function pb_send_magic_link_email($user, $mlink) {

  $to      =  $user->user_email;
  $subject =  'Your link to login to '.get_bloginfo('name');
  $headers =  'From: '.get_bloginfo('name').' Admin <'.get_bloginfo("admin_email").'>' . "\r\n" .
              'Reply-To: '.get_bloginfo("admin_email") . "\r\n" .
              'X-Mailer: WordPress/MagicLink' . "\r\n" .
              'Content-Type: text/html; charset=UTF-8' . "\r\n";

  $email_body = '<html>
  <body style="background: #ffffff;-webkit-font-smoothing: antialiased;-moz-osx-font-smoothing: grayscale;">
  <div style="max-width: 560px;padding: 20px;background: #ffffff;border-radius: 8px;margin:40px auto;font-family: Open Sans,Helvetica,Arial;font-size: 15px;color: #666; border: 3px solid #f2f2f2;">
  <div style="color: #000000;font-weight: normal;">
    <div style="text-align: center;font-weight:600;font-size:26px;padding: 10px 0;border-bottom: solid 3px #eeeeee;"><img src="https://via.placeholder.com/270x70?text='.urlencode(get_bloginfo('name')).'"></div>
    <div style="clear:both"></div>
  </div>  
  <div style="padding: 20px 20px 20px 20px">
    <div style="padding: 30px 0;font-size: 16px;text-align: left;line-height: 20px;color #000000;">';

  if (strlen($user->user_nicename)) {
    $email_body .= '<p style="color #000000;">Hello '.$user->user_nicename.',</p>';
  }

  $email_body .= '<p style="padding: 30px 0; color #000000;">Sorry you are having problems logging into '.get_bloginfo('name').'. Here is a magic login link you can use. It is valid for '.PB_MAGIC_LINK_VALID_MINUTES.' minutes from the time it was requested which works out to be '.date("m/d/Y g:i:s a e",((int)$mlink['time'] + ((int)PB_MAGIC_LINK_VALID_MINUTES * 60))).'. The link will also expire once it is used.</p>';

  $email_body .= '<div style="padding: 30px 0 40px 0;text-align: center;"><a href="'.PB_MAGIC_LINK_LOGIN_URL."?ml=".$mlink['code'].'" style="background: #555555;color: #fff;padding: 12px 30px;text-decoration: none;border-radius: 3px;letter-spacing: 0.3px;">Login to Wordpress</a></div>';

  $email_body .= '<p style="padding: 30px 0; color #000000;">If you did not make this request, ignore this email or report it to us by replying to this email.</p>';

  $email_body .= '<p style="padding: 30px 0; color #000000;">If you are still having problems logging in, or this link is not working for you, just reply to this message with details and we will do what we can to help.</p>';

  $email_body .= '<div style="padding: 30px 0; color #000000;">
      <p style="color #000000;">Cheers,</p>
      <p style="color #000000;">The <a href="'.get_bloginfo('url').'" style="color: #000000;text-decoration: none;">'.get_bloginfo('name').'</a> Team</p>
    </div>';

  $email_body .= '</div></div></div>';

  $success = mail($to, $subject, $email_body, $headers);

  if ($success) {
    return true;
  } else {
    $errorMessage = error_get_last()['message'];
    mail (get_bloginfo("admin_email"), "[MLL] Error sending magic link email to $to", $errorMessage."\n----------\n".$email_body,$headers);
    return false;
  }
}

function pb_magic_link_handle_token($magic_link_code) {

  //Checks code is valid, for the right user, and hasn't timed out
  $user = pb_verify_magic_link_code($magic_link_code);

  if (!$user || empty($user->ID)) {
    //Invalid
    wp_safe_redirect( home_url( ) );
    exit;
  }

  delete_user_meta( $user->ID, 'magic_link' );
 
   //Log the user out if they are logged in
  if ( is_user_logged_in() ) {
    wp_logout();
  }
  wp_clear_auth_cookie();

  //Log the user in
  clean_user_cache( $user->ID );
  wp_set_current_user( $user->ID );
  wp_set_auth_cookie( $user->ID, true, is_ssl() );
  update_user_caches( $user );
  wp_signon( array( 'user_login' => $user->data->user_login, 'user_pass' => $user->data->user_pass, 'remember' => true ) );

  //Ultimate Member version -- maybe
  //UM()->user()->auto_login( $user->ID, true );

  do_action( 'pb_magic_link_handle_token_success', $user );

  wp_safe_redirect( PB_MAGIC_LINK_SUCCESS_URL );
  exit;
}

function pb_magic_link_handle_token_wordpress() {
  global $pagenow;
  if ( 'wp-login.php' == $pagenow && !empty($_GET['ml'])) {
    pb_magic_link_handle_token($_GET['ml']);
  }
  return;
}
//Hook into init and check if WP login page
add_action( 'init', 'pb_magic_link_handle_token_wordpress' );

// Show the request magic link form
// NOTE: uses Ultimate Member styles
function pb_request_magic_link() {
  ob_start();

  unset($status);
  if (is_user_logged_in()) {
    //This is not for you.
    $status = "loggedin";
  } else {
    if (wp_verify_nonce( $_POST['_wpnonce'], "request_magic_link" )) {
      if (!empty($_POST['username_req'])) {
        //Respond with sent no matter what happens below
        $status = "sent";
        if (!$user = get_user_by("email", $_POST['username_req'])) {
          $user = get_user_by("login", $_POST['username_req']);
        }
        if (!empty($user)) {
          $mlink = pb_make_and_save_magic_link($user->ID, $user->user_email);
          pb_send_magic_link_email($user, $mlink);
        } else {
          //Be silent on not found
        }
      }
    }
  }

?>
<div class="um" style="max-width: 450px;">
  <div class="um-form">
      <?php if ( isset( $status ) ) { ?>
        <div class="um-field um-field-block um-field-type_block">
          <div class="um-field-block">
            <div style="text-align:center;">
            <?php if ( 'sent' == $status ) { ?>
              If a user with that username or email was found, we have emailed a login link to their email address.
            <?php } ?>
            <?php if ( 'loggedin' == $status ) { ?>
              You are already logged in. Continue to the <a href="/">homepage</a>.
            <?php } ?>
            </div>
          </div>
        </div>
      <?php } else { ?>
      <form method="post" action="">
        <?php wp_nonce_field('request_magic_link'); ?>
        <div style="text-align:center;">
          To request a login link, please enter your email address or username below and click the button.
          <input autocomplete="off" type="text" name="username_req" id="username_req" value="<?php if ($_GET['userid']) { echo $_GET['userid']; } ?>" placeholder="Enter your username or email" data-validate="" data-key="username_req">
            <input type="submit" value="Request Magic Login Link" />
        </div>
     <?php } ?>
    </form>
  </div>
</div>
<?php
  $result = ob_get_contents();
  ob_end_clean();
  return $result;

}
add_shortcode("request_magic_link", "pb_request_magic_link");


function base64url_encode($data) { 
  return rtrim(strtr(base64_encode($data), '+/', '-_'), '='); 
} 

function base64url_decode($data) { 
  return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT)); 
} 

?>