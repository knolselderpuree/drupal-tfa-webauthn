# drupal-tfa-webauthn

## Name
drupal-tfa-webauthn.

## Description
This plugin is an add-on for the drupal-tfa plugin. It allows users to use WebAuthn for 2 factor authentication. The plugin works with [JWT tokens](https://github.com/lcobucci/jwt) for extra security and is based on the [Firehed U2F library](https://github.com/Firehed/u2f-php).

## Installation
You can install this plugin with
> 
>composer require drupal/webauthn
>

## Testing (with WampServer64)
So far I have created a couple of tests, but the main tests are still missing, there needs to be a virtual authenticator available.
The test work with [PHPUnit](https://www.drupal.org/docs/automated-testing/phpunit-in-drupal) and [ChromeDriver](https://chromedriver.chromium.org/downloads).

For PHPUnit make sure you configure _MINK_DRIVER_ARGS_WEBDRIVER_ inside phpunit.xml as 
>
> ["chrome", {"browserName":"chrome","chromeOptions":{"args":["--disable-gpu", "--headless", "--disable-dev-shm-usage", "--ignore-certificate-errors", "--ignore-ssl-errors"]}}, "http://localhost:4444/wd/hub"]
>

Then run your Chromedriver with the command
>
> chromedriver.exe --url-base=/wd/hub --port=4444
>

And run your tests with, assuming you run the test from root and your phpunit.xml file is located in root:
>
> vendor\bin\phpunit -v -c \phpunit vendor\bin\webauthn\tests\src\FunctionalJavascript
>

## Author
The plugin was created by Bert Vandycke during an internship at Groupflights Belgium.
