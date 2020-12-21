#! /usr/bin/perl -w

# check_freeswitch_health.pl
#
# Written by Khalid J Hosein, Platform28, http://platform28.com
# July 2013
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Many thanks to Ton Voon for writing the Nagios::Plugin Perl module
#   http://search.cpan.org/~tonvoon/Nagios-Plugin-0.36/
#
# Switch from Nagios::Plugin to Monitoring::Plugin library
#
# Remember to modify the $fs_cli_location variable below to suit your install.
#
# The queries that you can pass to this plugin *resemble* but *do not*
# completely match queries that you can give fs_cli (in the -x argument)
# The reason for this is that those queries sometimes spit back too
# much data to process in one Nagios check. Additionally, they've all
# been transformed to hyphenated versions in order not to trip up NRPE.
#
# Note that since it's less complicated for Nagios to deal with one check at a 
# time, this script only accepts one (1) -q query.
#
# Checks that you can run currently and what type of results to expect:
#  sofia-status-internal - looks for the 'internal' Name and expects to
#       find a state of RUNNING. Sets the result to 1 if successful, 0 otherwise.
#       You'll need to set -c 1:1 (or -w 1:1) in Nagios if you want to
#       alert on it. See Nagios Thresholds for more info:
#       http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT
#       This check also returns # of calls as performance data.
#  sofia-status-external - looks for the 'external' Name and expects to
#       find a state of RUNNING. Same format as the 'internal' test above.
#  sofia-status-external-ipv6 - looks for the 'external-ipv6' Name and expects to
#       find a state of RUNNING. Same format as the 'internal-ipv6' test above.
#  show-calls-count - reports total # of current calls.
#  sofia-status-profile-internal-failed-calls-in - reports the FAILED-CALLS-IN
#       parameter in the 'sofia status profile internal' query.
#  sofia-status-profile-internal-failed-calls-out - reports the FAILED-CALLS-OUT
#       parameter in the 'sofia status profile internal' query.
#  show-registrations-count - reports total # of current registrations.
#

# TO DO IN FUTURE VERSIONS:
# 1. (DONE) Include an option (perhaps -a) to list all allowed queries.
#       Decided to refer the user back to the docs in the comments.
# 2. (DONE) Remove excess whitespace from $rawdata
# 3. Refine the use of the $perfdatatitle (better logic on selecting the title)
# 4. Look for fs_cli, and report back via cmd line output and perfdata if can't find



# I. Prologue
use strict;
use warnings;

# Look for 'feature' pragma (Perl 5.10+), otherwise use Switch module (Perl 5.8)
eval {
  # require feature 'switch';
  require feature;
  feature->import();
};
unless($@) {
  use Switch 'Perl6';
}

use Monitoring::Plugin;
use XML::LibXML;

# use vars qw($VERSION $PROGNAME $result);
our ( $VERSION, $PROGNAME, $result, $rawdata );
$VERSION = '0.5';

# get the base name of this script for use in the examples
use File::Basename;
$PROGNAME = basename( $0 );

# Fully qualified path to fs_cli. Modify this to suit:
my $fs_cli_location = "/usr/bin/fs_cli";

# Declare some vars
my $fs_cli_output;
my $fs_status;
my $dom;
my $profile;
my $gateway;
my $attribute;
my $result2;
my $label2;

my @allowed_attributes_profile = ( 'url',
				   'tls-url',
				   'registrations',
				   'failed-calls-in',
				   'failed-calls-out'
    );

my @allowed_attributes_gateway = ( 'to',
				   'failed-calls-in',
				   'failed-calls-out'
    );


# II. Usage/Help
my $p = Monitoring::Plugin->new(
    usage => "Usage: %s 
         --profile=name of SIP profile
                   e.g. internal, external, internal-ipv6
       [ --gateway=name of gateway ]   
       [ -w|--warning=threshold that generates a Nagios warning ]
       [ -c|--critical=threshold that generates a Nagios critical warning ]
       [ -f|--perfdatatitle=title for Nagios Performance Data. 
                            Note: don't use spaces. ]

       See the documentation in this script's comments for accepted queries.
       For example, you can run 'head -n 50 check_freeswitch_health.pl'
       ",
    version => $VERSION,
    blurb   => "This plugin requires the FreeSWITCH fs_cli command to perform checks.",
    extra   => qq(
    An example query:   
    ./check_freeswitch_health.pl -q show-calls-count -w 100 -c 150 -f Total_Calls
    ),
    license =>
      "This Nagios plugin is subject to the terms of the Mozilla Public License, v. 2.0.",
);

# III. Command line arguments/options
# See Getopt::Long for more
$p->add_arg(
    spec     => 'profile=s',
    required => 1,
    help     => "--profile=STRING
    What profile to check. E.g. internal, external, external-ipv6 etc. 
    REQUIRED."
    );

$p->add_arg(
    spec => 'gateway=s',
    help => "--gateway=STRING
    What gateway to check within a profile"
);

$p->add_arg(
    spec => 'attribute=s',
    default => 'url',
    help => "--attribute=STRING
    What attribute to check of profile or gateway: url, tls-url, to, registrations, calls-in, calls-out, failed-calls-in, failed-calls-out"
);

$p->add_arg(
    spec => 'warning|w=s',
    help => "-w, --warning=INTEGER:INTEGER
    Minimum and maximum number of allowable result, outside of which a
    warning will be generated. If omitted, no warning is generated."
);

$p->add_arg(
    spec => 'critical|c=s',
    help => "-c, --critical=INTEGER:INTEGER
    Minimum and maximum number of allowable result, outside of which a
    an alert will be generated.  If omitted, no alert is generated."
);

$p->add_arg(
    spec     => 'perfdatatitle|f=s',
    required => 0,
    help     => "-f, --perfdatatitle=STRING
    If you want to collect Nagios Performance Data, you may
    give the check an appropriate name. OPTIONAL"
);

# Parse arguments and process standard ones (e.g. usage, help, version)
$p->getopts;

# IV. Sanity check the command line arguments
# Ensure that only one of the supported fs_cli queries are called:

$fs_cli_output = `$fs_cli_location -x "sofia xmlstatus"`;
$dom = XML::LibXML->load_xml(string => $fs_cli_output);

my $calls;
my @profiles;
$profile = $p->opts->profile;
foreach my $node ($dom->findnodes('./profiles/profile')) {
    my $prf = $node->findvalue('./name');
    push( @profiles, $prf );
    if ( $prf eq $profile ) {
	my $state =  $node->findvalue('./state');
	if( $state =~ /\((\d+)\)/ ){
	    $calls = $1;
	}
	last;
    }
}

unless( grep /^$profile$/, @profiles ){
    $p->nagios_exit( CRITICAL, join( ' ', "Sorry, that's not an running profile ($profile)!",
				     'Available:', join( ', ', @profiles ) ) );
}



my @gateways;
$gateway = $p->opts->gateway;
$attribute = $p->opts->attribute;
if ( defined $gateway ) {
    foreach my $node ($dom->findnodes('./profiles/gateway')) {
	my $gtw = $node->findvalue('./name');
	push( @gateways, $gtw );
	if ( $gtw eq $gateway ) {
	    last;
	}
    }
    unless( grep /^$gateway$/, @gateways ){
	$p->nagios_exit(  CRITICAL, join( ' ', "Sorry, that's not an running gateway ($gateway)!",
					  'Available:', join( ', ', @gateways ) ) );
    }
    # set default attribute
    if ( $attribute eq 'url' ){
	$attribute = 'to';
    }
}

my $perfdatatitle;
unless ( defined $gateway ) {
    
    $perfdatatitle = join( '/', 'sofia', 'status', $profile, $attribute );
    $fs_cli_output = `$fs_cli_location -x "sofia xmlstatus profile $profile"`;
    $dom = XML::LibXML->load_xml(string => $fs_cli_output);
    
    my $path = './profile/profile-info';
    given( $attribute ){
	when('url') {
	    my $url = $dom->findvalue("$path/$attribute");
	    if ( defined $url ) {
		$result = 1;
	    } else {
		$result = 0;
	    }
	    $result2 = $calls;
	    $label2 = '# of calls';
	    $rawdata = join( ' ', $url, 'RUNNING' );
	}
	when('tls-url'){
	    
	    my $tls_url = $dom->findvalue("$path/$attribute");
	    if ( defined $tls_url ) {
		$result = 1;
	    } else {
		$result = 0;
	    }
	    $result2 = $calls;
	    $label2 = '# of calls';
	    $rawdata = join( ' ', $tls_url, 'RUNNING (TLS)' );
	}
	when('registrations') {
	    $result = $dom->findvalue("$path/registrations");
	    $rawdata = join( ' ', $result, 'total' );
	}
	when('failed-calls-in'){
	    $result = $dom->findvalue("$path/failed-calls-in");
	    $rawdata = join( ' ', $result, 'total' );
	}
	when('failed-calls-out'){
	    $result = $dom->findvalue("$path/failed-calls-out");
	    $rawdata = join( ' ', $result, 'total' );
	}
	default {
	    $p->nagios_die( join(' ', "Sorry, that's not an allowed attribute for profile (attribute=$attribute)!",
		'Allowed:', join( ', ', @allowed_attributes_profile ) ) );
	}
    }

} else {
    $perfdatatitle = join ( '/', 'sofia', 'status', $gateway, $attribute );
    $fs_cli_output = `$fs_cli_location -x "sofia xmlstatus gateway $gateway"`;
    $dom = XML::LibXML->load_xml(string => $fs_cli_output);
    my $state = $dom->findvalue('./gateway/state');
    my $status = $dom->findvalue('./gateway/status');
    my $to = $dom->findvalue('./gateway/to');

    given( $attribute ) {
	when('to'){
	    if ( $state eq 'REGED' and $status eq 'UP' ) {
		$result = 1;
	    } else {
		$result = 0;
	    }
	    $rawdata = join( ' ', $to, $state, '('.$status.')'); 
	}
	when('failed-calls-in'){
	    $result = $dom->findvalue('./gateway/failed-calls-in');
	    $rawdata = join( ' ', $result, 'total' );
	}
	when('failed-calls-out'){
	    $result = $dom->findvalue('./gateway/failed-calls-out');
	    $rawdata = join( ' ', $result, 'total' );
	}
	default {
	    $p->nagios_die( join(' ', "Sorry, that's not an allowed attribute for gateway (attribute=$attribute)!",
		'Allowed:', join( ', ', @allowed_attributes_gateway ) ) );
	}
    }
}


# VI. Performance Data gathering

my $threshold = $p->set_thresholds(
    warning  => $p->opts->warning,
    critical => $p->opts->critical
);


if ( defined $p->opts->perfdatatitle ) {
    $perfdatatitle = $p->opts->perfdatatitle;
}
$perfdatatitle =~ s/\s/_/g;    # replace whitespaces with underscores

$p->add_perfdata(
    label     => $perfdatatitle,
    value     => $result,
    threshold => $threshold,
    uom       => "",               # Bug in Nagios::Plugin version 0.15 (required for Monitoring::Plugin?)
);

# is there a 2nd set of performance data:
if ( defined $result2 ) {
    $p->add_perfdata(
        label => $label2,
        value => $result2,
        uom   => "",               # Bug in Nagios::Plugin version 0.15 (required for Monitoring::Plugin?)
    );
}

# VIII. Exit Code
# Output in Nagios format and exit.

# remove excess whitespace:
$rawdata =~ s/\s+/ /g;

$p->nagios_exit(
    return_code => $p->check_threshold( $result ),
    message     => "Result of check is: $rawdata",
);
