#!/usr/bin/perl

use strict;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => "Mail::Decency",
    VERSION_FROM     => "lib/Mail/Decency.pm",
    EXE_FILES        => [ "script/decency-server.pl" ],
    PREREQ_PM        => {
        'Archive::Tar' => '1.40',
        'Cache::FastMmap' => 0,
        'Cache::File'  => 0,
        'Cache::Memcached'  => 0,
        'Crypt::OpenSSL::RSA'  => 0,
        'DBD::SQLite'  => 0,
        'DBI'  => 0,
        'DBIx::Connector'  => 0,
        'Getopt::Long'  => 0,
        'IO::File'  => 0,
        'IO::Handle'  => 0,
        'IO::Pipe'  => 0,
        'IO::Socket'  => 0,
        'IO::YAML' => '0.08',
        'IPC::Semaphore' => '2.01',
        'IPC::SysV' => '2.01',
        'MIME::Lite'  => 0,
        'MIME::Parser'  => 0,
        'MIME::QuotedPrint'  => 0,
        'Mail::DKIM' => '0.38',
        'Moose' => '1.00',
        'Net::Domain::TLD'  => 0,
        'Net::DNS'  => 0,
        'Net::Milter'  => 0,
        'Net::Netmask'  => 0,
        'Net::SMTP'  => 0,
        'POE'  => 0,
        'POE::Filter::Postfix::Plain'  => 0,
        'POE::Wheel::ReadWrite'  => 0,
        'POE::Wheel::SocketFactory'  => 0,
        'SQL::Abstract'  => 0,
        'Throwable'  => 0,
        'version' => '0.77',
        'YAML'  => 0,
    }
);

