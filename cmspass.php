<?php
/*
 * cmspass.php
 *
 * allows changing of cms passwords via cmd line
 * 
 * Andrew D.
 */

abstract class BaseCMS {

    protected $host;
    protected $user;
    protected $pass;
    protected $dbname;
    protected $location;
    protected $prefix;
    protected $cms;
    protected $uname;

    protected function randpass(){
        $charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.
            'abcdefghijklmnopqrstuvwxyz0123456789';

        $str = '';
        $count = strlen($charset);
        for ($i = 0; $i <= 9; $i++) {
            $str .= $charset[mt_rand(0, $count-1)];
        }

        return $str;
    }

    abstract protected function adminQuery();
    abstract protected function chpassQuery($data, $password);

    public function run() {

        mysql_connect($this->host, $this->user, $this->pass)
            or die(mysql_error());

        mysql_select_db($this->dbname) or die(mysql_error());

        $result = mysql_query($this->adminQuery()) or die (mysql_error());

        print "\n[".$this->cms."] Location: ".$this->location."\n===\n";
        while ($data = mysql_fetch_array($result)) {
            $password = $this->randpass();
            mysql_query($this->chpassQuery($data, $password)) or die (mysql_error());

            print $data[$this->uname]." - ".$password."\n";
        }
        print "===\n";

        mysql_close();
    }
}


class WpCMS extends BaseCMS {

    function __construct($dir) {
        $this->location = dirname(realpath($dir."/wp-config.php"));
        $wpconfig = $this->wphack($dir."/wp-config.php");
        require($wpconfig);

        $this->host = DB_HOST;
        $this->user = DB_USER;
        $this->pass = DB_PASSWORD;
        $this->dbname = DB_NAME;
        $this->prefix = $table_prefix;
        $this->cms = "WordPress";
        $this->uname = "user_login";

        unlink('./wpresstmp.php');
    }

    // what is this hack you say? WordPress was horribly designed so that when
    // you include wp-config.php the entire WordPress backend is loaded as well.
    // Maybe all you want to do is change a password, but this script may 
    // fail because of a syntax error at wp-content/plugins/somethingrandom/data/system.php
    // line 37... :(  so I create a temp wp-config.php which loads no further files
    // so we can at least change the damn password
    protected function wphack($confFile) {
        $tmp = './wpresstmp.php';
        copy($confFile, $tmp);
        //$evil = "require_once(ABSPATH . 'wp-settings.php');";
        $evil = "/require_once\(\s*?ABSPATH.*?'wp-settings.php'\s*?\);/";
        $data = file_get_contents($tmp);
        //$data = str_replace($evil,"",$data);
        $data = preg_replace($evil,"",$data);
        file_put_contents($tmp, $data);

        return $tmp;
    }

    protected function adminQuery() {
        return "SELECT um.user_id AS id, u.user_login FROM ".$this->prefix.
            "users u,".$this->prefix."usermeta um WHERE u.id = um.user_id ".
            "AND um.meta_key = '".$this->prefix."capabilities' AND ".
            "um.meta_value LIKE '%administrator%'";
    }

    protected function chpassQuery($data, $password) {
        return "UPDATE ".$this->prefix."users SET user_pass = MD5('".
            $password."') WHERE id=".$data['id'];
    }
}


class JoomlaCMS extends BaseCMS {

    function __construct($dir) {
        $this->location = dirname(realpath($dir."/configuration.php"));
        require($dir."/configuration.php");

        $joomla = new JConfig();
        $this->host = $joomla->host;
        $this->user = $joomla->user;
        $this->pass = $joomla->password;
        $this->dbname = $joomla->db;
        $this->prefix = $joomla->dbprefix;
        $this->cms = "Joomla";
        $this->uname = "username";
    }

    protected function adminQuery() {

        if (mysql_query("DESCRIBE ".$this->prefix."core_acl_aro")) {
            return "SELECT id,username FROM ".$this->prefix."users WHERE usertype".
                " LIKE '%administrator%'";
        } else {
            return "SELECT id,username FROM ".$this->prefix."users LEFT JOIN ".
                $this->prefix."user_usergroup_map ON (id = user_id) WHERE ".
                "group_id = 8";
        }
    }

    protected function chpassQuery($data, $password) {

        return "UPDATE ".$this->prefix."users SET password=MD5('".$password.
            "') WHERE id=".$data['id'];

    }
}


class CMSFactory {

    public static function create($dir) {

        if (file_exists($dir.'/wp-config.php')) {
            return new WpCMS($dir);
        } elseif (file_exists($dir.'/configuration.php')) {
            return new JoomlaCMS($dir);
        } else {
            return null;
        }
    }
}

// for our basic purposes we don't really need to use the PHP option parser
// (also its terrible)
$dir = ".";
if (sizeof($argv) > 1) {
    $dir = $argv[1];
}

$cms = CMSFactory::create($dir);
if ($cms == null) {
    file_put_contents('php://stderr', "Could not find CMS!\n");
    exit(1);
}


$cms->run();
