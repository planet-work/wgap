#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2014-2015 Planet-Work <f.vanniere@planet-work.com>
# Source: https://github.com/planet-work/php-malware-scanner
# License: MIT
# https://github.com/planet-work/php-malware-scanner/blob/master/LICENSE

import os
import re
import fnmatch

whitelist = [
  '/._',
  'cache/object/000000/',
  'libraries/simplepie/simplepie.php',
  '/smarty/cache/',
  'SimplePie/Misc.php',
  'libraries/phpxmlrpc/xmlrpc.php',
  '/typography/googlefonts.php',
  '/var/cache/deliverycache_',
  'GPAO/ajouter_clients.php',
  '/GPAO/modifier_clients2.php',
  'libraries/openid/Auth/OpenID/Consumer.php',
  '/includes/utf/data/',
  'libraries/openid/Auth/OpenID/Association.php',
  '/module_courriel/form_courriel.php',
  '/pro-settings.php',
  '/themes/MmoPress/header.php',
  '/themes/MmoPress/functions.php',
  'tcpdf.php',
  '/wp-includes/upgrade.php',
  '/includes/et_lb_sample_layouts.php',
  '/sp_compatibility_test.php',
  '/tmp/cache/skel/html____',
  '/assets/styles/css-',
  '/help.inc.php',
  'achat/fin_commande.php',
  '/accessibility.inc.php',
  '/optimizePressPlugin/lib/',
  '/wfBrowscapCache.php',
  'kick-it-2x/footer.php',
  '/blueidea-10/footer.php',
  '/three_tennis_balls_scoreboard_spj005/footer.php',
  '/page-google-maps/view/widget_js.php',
  '/gardens-amidst-jungle/footer.php',
  '/With_Rainbows/footer.php',
  '/naturetravel/footer.php',
  '/pages/1250793045.php',
  '/tinymce/preview.php',
  'polldata/session.php',
  '/tmplvars.inc.php',
  '/Command/Factory/FactoryInterface.php',
  '/Service/Exception/DescriptionBuilderException.php',
  'iconic-navigation/iconavs_icons.php',
  '/classes/TinyPspellShell.class.php',
  'aklazy/aklazy/main.php',
  '/inc/RecupDocsTheme.php',
  '/function.eval.php',
  '/trans_box.php',
  'newstoday/footer.php',
  '/md_mix.inc.php',
  '/import.inc.php',
  '/cache/twig/',
  '/transliteration/data/',
  '/Transliterator/data/x',
  '/patterns/',
  '/ecrire/lang/public_',
  'phocagallery/render/renderinfo.php',
  'Faker/Provider',
  '/ecrire/lang/ecrire_',
  '/ecrire/lang/spip_',
  '/symfony/vendors.php',
  'stat/images/os.php',
  'js_composer/config/templates.php',
  'leaflet-maps-marker/leaflet-exportcsv.php',
  '/auth/iso639-2.php',
  '/includes/lang/.*\.inc\.php',
  '.yml.php',
  '.js.php',
  'cache/siteCache.idx.php',
  '/wpsr-services-selector.php',
  '/mpdf56/examples',
  '/mpdf50/examples',
  'wp-admin-bar-removal/wp-admin-bar-removal.php',
  'includes/admin/dummy.php',
  'tcpdf/fonts/',
  '/shortcodes/googlemaps.php',
  '/infocus/activation.php',
  'admin/core/core-help-text.php',
  '/theme-check/checks/badthings.php',
  '_compatibility_test/sdk_compatibility_test.php',
  'compatibility_test/sp_compatibility_test.php',
  '/panel/shortcodes/ui.php',
  'tcpdf/fonts/pdfasymbol.php',
  'libraries/facebook-php-sdk/src/base_facebook.php',
  'Auth/NTLMAuthenticatorTest.php',
  'vendor/vendors.php',
  '/bin/vendors.php',
  'ap_ProdProjectContainer.php',
  'lib/htmLawed.php',
  '/editors/xinha.php',
  '/akismet/views/notice.php',
  'System/Model/Base/RouteGateway.php',
  'System/Model/Base/AdminrouteGateway.php ',
  'Comment/Model/Base/PostGateway.php',
  '/Sluggable/Util/data/x',
  '/ttfontdata/',
  'GDEFdata.php',
  'includes/facebook-php-sdk/base_facebook.php',
  'wp-content/plugins/wysija-newsletters/helpers/render_engine.php',
  'wp-content/plugins/wysija-newsletters/views/back/campaigns.php',
  'wp-content/plugins/wysija-newsletters/helpers/render_engine.php',
  'wp-content/plugins/broken-link-checker/idn/uctc.php',
  'wp-includes/class-IXR.php',
  'wp-includes/SimplePie/Sanitize.php',
  'wp-admin/includes/ajax-actions.php',
  'wp-content/plugins/codestyling-localization/codestyling-localization.php',
  '/nusoap.php',
  'shortcodes/vc_raw_html.php',
  '/class-pclzip.php',
  '/pclzip/pclzip.lib.php',
  '/pclzip/pclzip.php',
  '/inc_php/framework/base_admin.class.php',
  'wp-includes/class-wp-atom-server.php',
  'wp-includes/class-simplepie.php',
  'wp-includes/class-wp-customize-widgets.php',
  'wp-admin/includes/file.php',
  'wp-admin/js/revisions-js.php',
  '/wp-app.php',
  '/CallbackColumn.php',
  'sitepress-multilingual-cms/res/languages.csv.php',
  'content/plugins/better-wp-security/core/class-itsec-core.php',
  'content/plugins/w3-total-cache/lib/W3/Plugin/Minify.php',
  'content/plugins/w3-total-cache/lib/SNS/sdk.class.php',
  'content/plugins/codestyling-localization/codestyling-localization.php',
  '_tcpdf/tcpdf.php',
  'tcpdf/examples/example_',
  'src/ext/htmlsql.class.php',
  'plugins/wplite/wplite.php',
  'plugins/nospamnx/ws1.php',
  'bepro-listings/bepro_listings.php',
  '/wpposticon.php',
  '/better-wp-security/core/class-itsec-core.php',
  '/app/cache/dev/',
  '/app/cache/prod/',
  'administrator/components/com_remository/admin.remository.html.php',
  'administrator/components/com_remository/admin.remository.html.php',
  'ultimate-coming-soon-page/framework/framework.php',
  'wp-content/plugins/shortcodes-ultimate/inc/core/shortcodes.php',
  'wp-content/plugins/shortcodes-ultimate/inc/vendor/sunrise.php',
  'wp-content/plugins/ultimate-coming-soon-page/framework/framework.php',
  '/XmlRpcClientRemote/XmlRpc.php',
  'sitepress-multilingual-cms/inc/installer/includes/installer.class.php',
  '/Amf/Server.php',
  'src/facebook.php',
  '/spellchecker.php',
  'util/php/ajax/filters.php',
  'lib/class/SEO_URL.class.php',
  'ebservice/dispatcher.php',
  'include/js/jsval.php',
  'include/js/lytebox.php',
  'include/class.TCPDF.php',
  'SimplePie/Sanitize.php',
  'plugins/gravityforms/common.php',
  'plugins/gravityforms/form_detail.php',
  'gravityforms/includes/addon/class-gf-results.php',
  'w3-total-cache/inc/functions/multisite.php',
  '/ezpublish/cache/',
  'administrator/components/com_securitycheckpro/scans/',                        
  'custom-fields/typography/googlefonts-array.php',                              
  'wp-content/uploads/sucuri/sucuri-sitecheck.php',                              
  'wp-content/plugins/akeebabackupcore/app/restore.php',  
]

debug = True
line_early = 15
scoring = {
  'WHITELISTED':              (-10, u'fichier en whitelist manuelle'),
  'WHITELISTED_LINE':         (-10, u'ligne en whitelist manuelle'),
  'PHP_COMMENTS':             (-10, u'Fichier commence proprement avec une description'),
  'CLASS_FUNCTION':           (-10, u'Fonction ou classe definie au tout debut'),
  'BASE64_STRING':            (50, u'Motif base64 trouve'),
  'CRYPT_PHP':                (50, u'Script CryptPHP qui inclue social.png'),
  'PHP_SHELL':                (50, u'Script Shell'),
  'PHP_OBFUSC_SHELL':         (50, u'Script Shell cache'),
  'ACCESS_DENIED':            (-30, u'Execution bloquee en tout debut de fichier'),
  'JAVASCRIPT_HACK':          (50, u'Hack javascript'),
  'HAS_EVAL':                 (2, u'Contient eval()'),
  'HAS_EVAL_EARLY':           (10, u'Contient eval() en debut de fichier'),
  'HAS_CALL_FUNC_EARLY':      (3, u'Contient call_user_func() en debut de fichier'),
  'HAS_BASE64DECODE':         (2, u'Contient base64_decode() ou str_rot13()'),
  'HAS_BASE64DECODE_EARLY':   (10, u'Contient base64_decode() ou str_rot13() en debut de fichier'),
  'HAS_MAIL':                 (1, u'Contient mail()'),
  'HAS_MAIL_EARLY':           (2, u'Contient mail() en debut de fichier'),
  'LONG_LINE':                (5, u'Contient une ligne de plus de 1000 caracteres'),
  'LONG_LINE_EARLY':          (8, u'Contient une ligne de plus de 1000 caracteres debut de fichier'),
  'VERY_LONG_LINE':           (5, u'Contient une ligne de plus de 3000 caracteres'),
  'VERY_LONG_LINE_EARLY':     (9, u'Contient une ligne de plus de 3000 caracteres en debut de fichier'),
  'MD5_VAR':                  (10, u'Contient une variable encodee en MD5'),
  'INCLUDE_REQUIRE':          (-2, u'Contient include() ou require() sans http'),
  'COOKIE_FORM1':             (20, u'Contient form1=@$_COOKIE'),
  'MAIL_X_HEADER':            (5, u'Contient mail.add_x_header'),
  'SET_TIME_0':               (5, u'Contient set_time_limit(0)'),
  'SET_ERRORREPORTING_0':     (2, u'Contient error_reporting(0)'),
  'SET_TIMELIMIT_0':          (2, u'Contient memory_limit(0)'),
  'SET_IGNOREUSERABORT_0':    (2, u'Contient ignore_user_abort()'),
  'UPLOAD_FILE':              (2, u'Contient move_uploaded_file()'),
  'FEW_LINES':                (0, u'Contient peu de lignes'),
  'EMPTY_FILE':               (-100, u'Fichier vide'),
  'MANY_LINES':               (-2, u'Contient beaucoup de lignes'),
  'MANY_LINES2':              (-5, u'Gros fichier avec de lignes'),
  'MANY_LINES3':              (-10, u'Tres gros fichier avec de lignes'),
  'BAD_NEWLINES':             (-5, u'Ficher sur 1 ligne sans saut de ligne'),
  'NO_PHP_START':             (-5, u'Ne commence pas par <?'),
  'UA_GOOGLE':                (5, u'Verifie le User-Agent contre Google'),
  'EXEC_SHELL':               (5, u'Utilise system() ou shell_exec()'),
  'CONCAT_STRING':            (10, u'Chaine cachee par concatenation'),
  'MANY_GLOBALS':             (20, u'Contient tres souvent $GLOBALS'),
  'BIN_HOST':                 (10, u'contient /bin/host'),
  'SHELL_COMPACT':            (5, u'2eme ligne louche (shell?)'),
  'CURL_HTTP':                (5, u'telechargement HTTP'),
  'XXTEA_ENCRYPT':            (20, u'Code source encode avec XXTEA (possible ransomware)'),
}

def is_hacked(filename = None):
    if not filename:
        return False
    if '/cache/object/000000/' in filename or '/cache/db/000000/' in filename or \
            'cache/js-' in filename or 'cache/css-' in filename or '/css/css-' in filename:
        return False
    score = []
    line_num = 0
    clean_PCT4 = False
    clean_evalbase64 = False
    cleanup_available = False
    first_lines = []

    try:
        f = open(filename, 'rU')
    except IOError:
        return False

    for i in range(15):
        first_lines.append(f.readline().rstrip())
    f.close()

    f = open(filename, 'rU')

    php_code = f.read()
    php_code = php_code.replace("'.\n      '", '').replace('\'.\n\'', '')
    has_var_http = False
    has_long_line = False
    has_very_long_line = False
    previous_line = ''

    for w in whitelist:
        if w in filename:
            score.append(('WHITELISTED', w))

    # Javascript file
    if fnmatch.fnmatch(filename, '*.js'):
        for l in php_code.split('\n'):
            if 'eval(function(p,a,c,k,e,d)' in l and '|http|' in l and ('|blackberry|' in l) and not '|moxie' in l:
                score.append(('JAVASCRIPT_HACK', ''))
        total_score = 0
        score_details = []
        score_done = []
        for sco, detail in score:
            if sco in score_done:
                continue
            score_done.append(sco)
            total_score += scoring[sco][0]
            score_details.append({'rule': sco,
                                  'details': detail.encode('utf-8'),
                                  'score': scoring[sco][0],
                                  'description':  scoring[sco][1].encode('utf-8')})

        if filename[0] != '/':
            filename = os.getcwd() + '/' + filename

        return {'filename': filename,
                'score': total_score,
                'mtime': os.stat(filename).st_mtime,
                'ctime': os.stat(filename).st_ctime,
                'details': score_details,
                'cleanup': cleanup_available}

    # PHP file
    for l in php_code.split('\n'):
        if len(l.strip()) == 0:
            continue
        line_num += 1

        if l.strip()[0] in ['#', '*']:
            continue

        if l.count('"."') + l.count("'.'") > 50:
            score.append(('CONCAT_STRING', '%i concat' %
                         (l.count('","') + l.count("'.'"))))
        if l.count('$GLOBALS[') > 20:
            score.append(
                ('MANY_GLOBALS', '%i globals' % (l.count('","') + l.count("'.'"))))
        l = l.replace('","', '').replace("'.'", '')
        if ('die("Access Denied");' in l or '<?php return; ?>' in l or '<?php exit' in l or '<?php exit;?>' in l
           or l.find('<?php die (') == 0 or l.find('<?php die (') == 0
           or '<?php die(' in l or '<?php die; ?>' in l or '<?php /* Smarty version' in l
           or "if( !defined( '_VALID_MOS' )" in l or "if (!defined ('ABSPATH')" in l
           or "if (!defined('BB2_CORE'))" in l
           or l.find('<?php @Zend;') == 0
           or l.find('<?php defined(') == 0
           or (l.find('<?php /* The commercial version is not encoded. This file') == 0 and line_num == 1)
           or (l.find('// Before trying to crack the plugin, please consider buying a pro license at ') == 0 and line_num == 1)
           or l.find('<?php return array(') == 0
           or l.find("#<?php die('") == 0) and line_num == 1:
            score.append(('ACCESS_DENIED', ''))
        if l.find('/bin/host') >= 0:
            score.append(('BIN_HOST', ''))
        if ('if( !isset($gCms) ) exit;' in l or
           "if( !defined( '_VALID_MOS' )" in l or
            "if (!defined('IN_PHPBB')" in l or
            "defined('_JEXEC') " in l or "or more information: see languages.txt in the la" in l) \
           and line_num == 2:
            score.append(('ACCESS_DENIED', ''))
        # if 'Restricted access' in l:
        #    print line_num
        if line_num in [2, 3] and ('Direct Access to this location is not allo' in l or 'Restricted access' in l or 'defined(\'_JEXEC\') or die' in l):
            score.append(('ACCESS_DENIED', ''))
        if line_num == 1 and not l.strip().find('<?') == 0:
            score.append(('NO_PHP_START', ''))

        if line_num == 2 and (l.strip().find('class ') == 0 or l.strip().find('function ') == 0) and len(first_lines[0]) < 10:
            score.append(('CLASS_FUNCTION', ''))

        if re.compile('.*=\s*"[a-zA-Z0-9/=]{32}";').match(l):
            score.append(('MD5_VAR', ''))
        if re.compile('.*=\s*"http://[a-z0-9].*";').match(l) or re.compile(".*=\s*'http:.*';").match(l):
            if not 'simpletest.org' in l and not 'facebook.com' in l:
                has_var_http = True
        if has_var_http and ('curl_exec' in l or 'xxxxxxxxxx' in l) and line_num < 20:
            score.append(('CURL_HTTP', ''))
        if ('eval(' in l or 'eval (' in l) and not "eval('?>' . $contents);" in l and not "_eval(" in l:
            if line_num < line_early:
                score.append(('HAS_EVAL_EARLY', 'line %i' % line_num))
            else:
                score.append(('HAS_EVAL', 'line %i' % line_num))
        if l.find('mail(') == 0 or ' mail(' in l:
            if line_num < line_early:
                score.append(('HAS_MAIL_EARLY', 'line %i' % line_num))
            else:
                score.append(('HAS_MAIL', 'line %i' % line_num))
        if line_num < line_early and 'call_user_func' in l:
            score.append(('HAS_CALL_FUNC_EARLY', 'line %i' % line_num))

        if 'agent' in l.lower() and 'google' in l.lower():
            score.append(('UA_GOOGLE', ''))

        if 'base64_decode(' in l or 'base64_decode (' in l \
                or 'str_rot13(' in l or 'str_rot13 (' in l:
            if 'CmVycm9yX3JlcG9ydGluZygwKTsKJHFhe' in l or 'FZY1EuQIEkXvMlZ3yBBTrCVmLkH' in l or '<? /**/eval(base64_decode(' in l:
                score.append(('BASE64_STRING', ''))
                clean_evalbase64 = True
            elif line_num < line_early:
                score.append(('HAS_BASE64DECODE_EARLY', 'line %i' % line_num))
            else:
                score.append(('HAS_BASE64DECODE', 'line %i' % line_num))
        elif "<!-- :### -->" in l or 'b+=String.fromCharCode(a.charCodeAt(i)^2' in l or "eval(eval('String.fromCharCode(" in l:
            score.append(('JAVASCRIPT_HACK', ''))
        elif "'FilesMan';" in l or '"FilesMan";' in l or 'Web Shell by Guest' in l or 'File uppato senza problemi' in l or 'echo"<b>gagal"' in l \
             or "wpplugin_action = 'WPcheckInstall'" in l or "'bas'.'e6'.'4_d'.'ecode'" in l \
             or 'shell_exec("sh inst")' in l or 'index.php replaced successufuly!</font' in l \
             or 'Your browser does not support our Online Store' in l or '\\x62\\141\\x73\\145\\x36\\64\\x5f\\144\\x65\\143\\x6f\\144\\x65' in l \
             or '"b".""."as"."e"."".""."6"."4"."_"."de".""' in l \
             or 'ww.rootshell-team.info' in l \
             or "'bas'.'e6'.'4_d'.'ecode'" in l \
             or "'Upload files on server'" in l \
             or "'md5 cracker'," in l \
             or '"tar -xzpf"' in l\
             or 'convertIpToString($ip){return long2ip' in l\
             or 'dis Shell Commander' in l \
             or '"\\x52EQ\\x55E\\x53T_\\x55R\\x49"' in l\
             or '8Of6V9BaZ0kmlmTZua0V' in l \
             or '0LKuioz9grFttM2I0K' in l\
             or 'a5zNPHhK21eSn+FKZ' in l\
             or 'infectslab:' in l \
             or 'HV0X2J1ZmZlc' in l\
             or "file_get_contents('/etc/passwd" in l \
             or 'r57shell.net' in l \
             or 'CBF Team - Mailer' in l \
             or '[+] FOI</span>' in l \
             or 'NShell t35' in l \
             or 'CorporateSignonTelecode' in l \
             or 'UDP Shell!' in l \
             or 'eval("?>".gzuncompress(base64_decode(' in l \
             or 'Mr.HarchaLi' in l \
             or ('eval(gzinflate(base64_decode(' in l and line_num < 5)\
             or 'dropsforums.ru' in l \
             or 'DamaneDz' in l \
             or "$s='str_r'.'o'.'t13';" in l \
             or '){type1_send();exit();}elseif(isset' in l \
             or '\\x65\\x76\\x61\\x6c\\x20\\x28\\x20\\x67\\x7a\\x69\\x6e\\x66\\x6c\\x61\\x74' in l \
             or 'CH (UBS Spam) ' in l \
             or "$words['cantbeshown']" in l \
             or '"netstat -an' in l \
             or '($action==""||$password==""||$filename==""||$body=="")' in l \
             or "strrev('edoced_46esab')" in l \
             or (l.find("return base64_decode($") == 0 and 'for($i=0; $i < strlen($' in previous_line) \
             or 'function multiRequest($data, $options = array(), $oneoptions = array())' in l \
             or (l.find('GIF89') == 0 and line_num == 1) \
             or (line_num == 1 and "@$_COOKIE[" in l and "();}?>" in l) \
             or (line_num == 1 and '@move_uploaded_file' in l) \
             or ("move_uploaded_file/*;*/" in l) \
             or 'Database Emails Extractor' in l\
             or ("<h4>!PhpSend!</h4>" in l) \
             or '<b>Done ==> $userfile_name</b></center>' in l \
             or ('$files=fopen(\'../../../\'.$filepaths.' in l and ',"w+");' in l) \
             or "chmod ($_REQUEST['p1'], $_REQUEST['p2']);" in l \
             or "\\x62\\x61\\x73\\x65\\x36\\x34\\x5F\\x64\\x65\\x63\\x6F\\x64\\x65" in l\
             or (line_num == 2 and "$ref = $_SERVER['HTTP_USER_AGENT'];" in l) \
             or (line_num < 4 and "passthru($_POST[" in l) \
             or (line_num == 1 and '$stg="ba"."se"."64_d"."ecode";eval($stg(' in l) \
             or "file_put_contents('1.txt', print_r" in l:
            score.append(('PHP_SHELL', ''))

        if 'move_uploaded_file(' in l:
            score.append(('UPLOAD_FILE', ''))

        if ('<?php foreach(explode("\\' in l and line_num == 1) \
           or ('($_SERVER["\\x48\\124\\x54\\120\\x5f' in l and line_num == 1) \
           or (']) {move_uploaded_file($_FILES[' in l and line_num == 2) \
           or '*Wsfuvso!%x5c%x7825bss%x5' in l \
           or ('<?php eval(gzinflate(base64_decode' in l and "')));?>" in l ) \
           or (line_num == 1 and 'eval(' in l and '$_REQUEST[' in l and ' = fopen' in l and '; exit(); } ?>' in l) \
           or (line_num == 1 and 'if(!isset($GLOBALS[' in l) \
           or (line_num == 2 and 'if(!empty($_POST[' in l and '){eval($_POST' in l) \
           or (line_num == 2 and 'if(isset($_POST[' in l and 'eval($_POST[' in l) \
           or '%x5c%x7825-bubE' in l:
            cleanup_available = True
            score.append(('PHP_SHELL', ''))

        if ('"' in l or "'" in l) and not '$UTF8_TO_ASCII' in previous_line:
            if len(l) > 3000 and not has_very_long_line:
                has_long_line = has_very_long_line = True
                if line_num < line_early:
                    score.append(
                        ('VERY_LONG_LINE_EARLY', 'line %i' % line_num))
                else:
                    score.append(('VERY_LONG_LINE', 'line %i' % line_num))
            elif len(l) > 1000 and not has_very_long_line and not has_long_line:
                has_long_line = True
                if line_num < line_early:
                    score.append(('LONG_LINE_EARLY', 'line %i' % line_num))
                else:
                    score.append(('LONG_LINE', 'line %i' % line_num))

        if "$cidinfo['uni2cid'] = array(" in l or 'php return unserialize(' in l \
           or ('<?php // $Id: ' in l and line_num == 1) \
           or ('/////////////////////////////////////////////////////' in l and line_num == 2) \
           or ('* Squelette : ' in l and line_num == 3) \
           or ('bVRRb9owEH4eEv/hGrVzUhGYtmkPhYCqrdNe1' in l) \
           or ('<?php if(!function_exists("timezone_identifiers_list")){function timezone_identifi' in l) \
           or ('bVBBasMwELwX+odFF6UXCZ' in l) \
           or ('// ************************************************************' in l and line_num == 2):
            score.append(('WHITELISTED_LINE', ''))

        if 'form1=@$_COOKIE' in l:
            score.append(('COOKIE_FORM1', ''))
        if ('require_once(' in l or 'require(' in l or 'include(' in l) and not 'http' in l:
            score.append(('INCLUDE_REQUIRE', ''))
        if 'mail.add_x_header' in l:
            score.append(('MAIL_X_HEADER', ''))
        if 'set_time_limit(0)' in l or 'max_execution_time\',' in l or 'set_time_limit(' in l:
            score.append(('SET_TIME_0', ''))
        if 'error_reporting(0)' in l or 'error_reporting\',0' in l:
            score.append(('SET_ERRORREPORTING_0', ''))
        if 'ignore_user_abort(' in l or 'ignore_user_abort (' in l:
            score.append(('SET_IGNOREUSERABORT_0', ''))
        if 'memory_limit","-1"' in l or 'memory_limit",-1' in l:
            score.append(('SET_MEMORYLIMIT_0', ''))
        if ('system(' in l or 'system (' in l or 'shell_exec(' in l or 'shell_exec (' in l or 'passthru(' in l) and not 'filesystem' in l.lower():
            score.append(('EXEC_SHELL', ''))
        if 'PCT4BA6ODSE_' in l or 'eval($s21($s22))' in l or '$qV="stop_"' in l:
            score.append(('BASE64_STRING', ''))
            clean_PCT4 = True
        if 'include' in l and 'social.png' in l:
            score.append(('CRYPT_PHP', ''))
            cleanup_available = True
        if 'eval(xxtea_decrypt(base64_decode(' in l:
            score.append(('XXTEA_ENCRYPT', ''))
        previous_line = l

    if line_num < 20:
        score.append(('FEW_LINES', '%i lines' % line_num))
    elif line_num < 100:
        score.append(('MANY_LINES', '%i lines' % line_num))
    elif line_num < 1000:
        score.append(('MANY_LINES2', '%i lines' % line_num))
    else:
        score.append(('MANY_LINES3', '%i lines' % line_num))

    # Shell super bien cache, toutes les lignes ont la même longueur
    if len(first_lines) > 12 and line_num < 30  and first_lines[0] == '<?php' and \
            len(first_lines[1]) == len(first_lines[2]) == len(first_lines[3]) == len(first_lines[4]) == len(first_lines[5]) == len(first_lines[6]) == len(first_lines[7]) == len(first_lines[8]) and len(first_lines[3]) > 40 and first_lines[3][0] == ' ':
        score.append(('PHP_OBFUSC_SHELL', ''))

    if line_num == 0 or (line_num == 1 and ( len(first_lines[0]) < 10 or 'Silence is golden.' in first_lines[0])) \
            or (line_num == 2 and len(first_lines[0]) < 10 and 'Silence is golden.' in first_lines[1]):
        score.append(('EMPTY_FILE', ''))
    if line_num == 1 and ('<div' in first_lines[0] or 'class=' in first_lines[0]):
        score.append(('BAD_NEWLINES', ''))

    if line_num > 7 and (first_lines[0] == '<?php' or first_lines[0] == '<?') and first_lines[1] == '/**' and (first_lines[2].find(' * ') == 0 or first_lines[2].find('* ') == 0):
        score.append(['PHP_COMMENTS', w])
    if len(first_lines) > 3 and ('@author : ' in first_lines[1] or '@author : ' in first_lines[0] or '@version' in first_lines[2] or 'Legacy Mode compatibility' in first_lines[2]):
        score.append(['PHP_COMMENTS', w])

    total_score = 0
    score_details = []
    score_done = []
    for sco, detail in score:
        if sco in score_done:
            continue
        score_done.append(sco)
        total_score += scoring[sco][0]
        score_details.append({'rule': sco,
                              'details': detail.encode('utf-8'),
                              'score': scoring[sco][0],
                              'description':  scoring[sco][1]})

    if filename[0] != '/':
        filename = os.getcwd() + '/' + filename

    if clean_PCT4 or clean_evalbase64:
        cleanup_available = True
    if cleanup_available and line_num == 1:
        cleanup_available = False
    return {'filename': filename,
            'score': total_score,
            'mtime': os.stat(filename).st_mtime,
            'ctime': os.stat(filename).st_ctime,
            'details': score_details,
            'cleanup': cleanup_available,
            'excerpt' : '\n'.join(first_lines[0:4])}
    # print  total_score, filename, '::'.join(score_details).encode('utf-8')

    # from subprocess import Popen
    # if clean_PCT4:
    #    print "PCT4", filename, "CLEANED"
    #     Popen(['perl', '-pi', '-e','s/<\?php.*$sF=.PCT4B.*}\?>//g',filename])
    # elif clean_evalbase64:
    #    print "EVAL+BASE64", filename, "CLEANED"
    # Popen(['perl', '-pi',
    # '-e','s/\?php\s*eval\(base64_decode\("[a-zA-Z0-9\/=]*"\)\);/?php/g',filename])


