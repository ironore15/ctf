#!/bin/sh

echo 'enter one result of `hashcash -b 25 -m -r stegasaurus`'
echo -n '> '
read cash
(echo "$cash" | hashcash -d -c -b 25 -r stegasaurus) && ./stegasaurus

