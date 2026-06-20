#!/usr/bin/env bash
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos

# Backup current lists.json
cp lists.json /tmp/sprint7_t2_lists.bak

# Concurrent write test — simulate 2 admins creating different lists simultaneously
php -r '
require "lists.php";
$lists = json_decode(file_get_contents("lists.json"), true);
$lists["lists"][] = ["id"=>"test-race-A","name"=>"Race A","slug"=>"race-a","kind"=>"manual","side"=>"blacklist","system"=>false];
save_lists($lists);
' &
php -r '
require "lists.php";
sleep(0); // race-friendly
$lists = json_decode(file_get_contents("lists.json"), true);
$lists["lists"][] = ["id"=>"test-race-B","name"=>"Race B","slug"=>"race-b","kind"=>"manual","side"=>"blacklist","system"=>false];
save_lists($lists);
' &
wait

# At least one entry should exist (last-write-wins is OK, but the file must be valid JSON)
jq . lists.json >/dev/null || { echo "FAIL: lists.json corrupted (not valid JSON)"; cp /tmp/sprint7_t2_lists.bak lists.json; exit 1; }

# Restore
cp /tmp/sprint7_t2_lists.bak lists.json
echo "PASS: t2_save_lists"
