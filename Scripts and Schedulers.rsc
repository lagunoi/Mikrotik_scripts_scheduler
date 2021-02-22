# feb/18/2021 04:32:00 by RouterOS 6.49beta11
# software id = 302X-QBC1
#
# model = RB4011iGS+
# serial number = D4490C73D415
/system script
add dont-require-permissions=no name=Download_malc0de owner=HomeRouter \
    policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive source="\
    \n /tool fetch url=\"http://joshaven.com/malc0de.rsc\" mode=http;\
    \n :log info \"Downloaded malc0de.rsc from Joshaven.com\";\
    \n "
add dont-require-permissions=no name=Replace_malc0de owner=HomeRouter policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive source="\
    \n :foreach i in=[/ip firewall address-list find ] do={\
    \n :if ( [/ip firewall address-list get \$i comment] = \"malc0de\" ) do={\
    \n /ip firewall address-list remove \$i\
    \n }\
    \n }\
    \n /import file-name=malc0de.rsc;\
    \n :log info \"Removal old malc0de and add new\";\
    \n "
add dont-require-permissions=no name=Download_spamhaus owner=HomeRouter \
    policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive source="\
    \n /tool fetch url=\"http://joshaven.com/spamhaus.rsc\" mode=http;\
    \n :log info \"Downloaded spamhaus.rsc from Joshaven.com\";\
    \n "
add dont-require-permissions=no name=Replace_spamhaus owner=HomeRouter \
    policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive source="\
    \n :foreach i in=[/ip firewall address-list find ] do={\
    \n :if ( [/ip firewall address-list get \$i comment] = \"SpamHaus\" ) do={\
    \n /ip firewall address-list remove \$i\
    \n }\
    \n }\
    \n /import file-name=spamhaus.rsc;\
    \n :log info \"Removal old openbl and add new\";\
    \n "
add dont-require-permissions=no name=Download_dshield owner=HomeRouter \
    policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive source="\
    \n /tool fetch url=\"http://joshaven.com/dshield.rsc\" mode=http;\
    \n :log info \"Downloaded dshield.rsc from Joshaven.com\";\
    \n "
add dont-require-permissions=no name=Replace_dshield owner=HomeRouter policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive source="\
    \n :foreach i in=[/ip firewall address-list find ] do={\
    \n :if ( [/ip firewall address-list get \$i comment] = \"DShield\" ) do={\
    \n /ip firewall address-list remove \$i\
    \n }\
    \n }\
    \n /import file-name=dshield.rsc;\
    \n :log info \"Removal old dshield and add new\";\
    \n "
add dont-require-permissions=no name="FireHOL L2" owner=HomeRouter policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon source="/\
    ip firewall address-list\r\
    \n:local update do={\r\
    \n:do {\r\
    \n:local data ([:tool fetch url=\$url user=\$user password=\$password outp\
    ut=user as-value]->\"data\")\r\
    \n:local array [find dynamic list=blacklist]\r\
    \n:foreach value in=\$array do={:set array (array,[get \$value address])}\
    \r\
    \n:while ([:len \$data]!=0) do={\r\
    \n:if ([:pick \$data 0 [:find \$data \"\\n\"]]~\"^[0-9]{1,3}\\\\.[0-9]{1,3\
    }\\\\.[0-9]{1,3}\\\\.[0-9]{1,3}\") do={\r\
    \n:local ip ([:pick \$data 0 [:find \$data \$delimiter]].\$cidr)\r\
    \n:do {add list=blacklist address=\$ip comment=\$description timeout=1d} o\
    n-error={\r\
    \n:do {set (\$array->([:find \$array \$ip]-[:len \$array]/2)) timeout=1d} \
    on-error={}\r\
    \n}\r\
    \n}\r\
    \n:set data [:pick \$data ([:find \$data \"\\n\"]+1) [:len \$data]]\r\
    \n}\r\
    \n} on-error={:log warning \"Address list <\$description> update failed\"}\
    \r\
    \n}\r\
    \n\$update url=https://raw.githubusercontent.com/firehol/blocklist-ipsets/\
    master/dshield_top_1000.ipset description=\"FireHOL Level2\" delimiter=(\"\
    \\n\")\r\
    \n"
/system scheduler
add comment=Download_malc0de interval=3d name=Download_malc0de on-event=\
    Download_malc0de policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive start-date=\
    dec/29/2020 start-time=23:30:00
add comment=Replace_spamhaus interval=3d name=Replace_spamhaus on-event=\
    Replace_spamhaus policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive start-date=\
    dec/29/2020 start-time=23:37:00
add comment=Download_spamhaus interval=3d name=Download_spamhaus on-event=\
    Download_spamhaus policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive start-date=\
    dec/29/2020 start-time=23:35:00
add comment=Replace_malc0de interval=3d name=Replace_malc0de on-event=\
    Replace_malc0de policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive start-date=\
    dec/29/2020 start-time=23:32:00
add comment="Download dshield" interval=3d name=Download_dshield on-event=\
    Download_dshield policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive start-date=\
    dec/29/2020 start-time=23:42:00
add comment="Apply dshield" interval=3d name=Replace_dshield on-event=\
    Replace_dshield policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive start-date=\
    dec/29/2020 start-time=23:44:00
add comment="Check Upgrade Router" disabled=yes interval=1d name=\
    Upgrade_Router on-event="/system upgrade\r\
    \nrefresh\r\
    \n:delay  10\r\
    \ndownload 0\r\
    \n/\r\
    \n/system reboot  \r\
    \n:delay 60\r\
    \ny\r\
    \n/" policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive \
    start-date=dec/29/2020 start-time=02:00:01
add comment="FireHOL L2" interval=1d name="FireHOL L2" on-event="FireHOL L2" \
    policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon \
    start-date=dec/29/2020 start-time=23:55:00