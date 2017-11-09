#!/bin/bash

export KDEB_PKGVERSION=0.1-1
export KDEB_CHANGELOG_DIST=unstable
export DEBFULLNAME="Keith Packard"
export DEBEMAIL="packard@hpe.com"

KERNEL_BASE="linux-"
KERNEL_VERSION="4.8.0"
KERNEL_EXTRA="-l4fame"
KERNEL_GIT="+"
ARCH="amd64"

PACKAGE="${KERNEL_BASE}${KERNEL_VERSION}${KERNEL_EXTRA}${KERNEL_GIT}_${KDEB_PKGVERSION}_${ARCH}"

CHANGES=${PACKAGE}.changes

#cp linux-upstream/config.l4fame linux-upstream/.config

#(cd linux-upstream && make oldconfig) || exit 1

fakeroot make deb-pkg || exit 1

debsign ../$CHANGES || exit 1
dput l4fame ../$CHANGES
