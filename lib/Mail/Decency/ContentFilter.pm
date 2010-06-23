package Mail::Decency::ContentFilter;

use Moose;
extends qw/
    Mail::Decency::Core::Server
/;

with qw/
    Mail::Decency::Core::Stats
/;

use version 0.77; our $VERSION = qv( "v0.1.0" );

use feature qw/ switch /;

use Data::Dumper;
use Scalar::Util qw/ weaken blessed /;
use YAML;
use MIME::Parser;
use MIME::Lite;
use IO::File;
use Net::SMTP;
use File::Path qw/ make_path /;
use File::Copy qw/ copy move /;
use File::Temp qw/ tempfile /;
use Cwd qw/ abs_path /;
use Crypt::OpenSSL::RSA;
use Time::HiRes qw/ tv_interval gettimeofday /;


use Mail::Decency::ContentFilter::Core::Constants;
use Mail::Decency::Core::SessionItem::ContentFilter;
use Mail::Decency::Core::POEForking::SMTP;
use Mail::Decency::Core::Exception;

=head1 NAME

Mail::Decency::ContentFilter

=head1 SYNOPSIS

    use Mail::Decency::ContentFilter;
    
    my $content_filter = Mail::Decency::ContentFilter->new( {
        config => '/etc/decency/content-filter.yml'
    } );
    
    $content_filter->run;

=head1 DESCRIPTION

Postfix:Decency::ContentFilter implements multiple content filter

=head1 POSTFIX

You have to edit two files: master.cf and main.cf in /etc/postfix 


=head2 master.cf

Add the following to the end of your master.cf file:

    # the decency server itself
    decency	unix  -       -       n       -       2        smtp
        -o smtp_send_xforward_command=yes
        -o disable_dns_lookups=yes
        -o max_use=20
    
    # this is only required if you use virus or spam filters with bouncing
    decency-bounce unix	-	n	n	-	2	pipe
        flags=FR user=decency argv=/etc/decency/bouncer
    
    # re-inject mails from decency for delivery
    127.0.0.1:10250      inet  n       -       -       -       -       smtpd
        -o content_filter= 
        -o receive_override_options=no_unknown_recipient_checks,no_header_body_checks,no_milters
        -o smtpd_helo_restrictions=
        -o smtpd_client_restrictions=
        -o smtpd_sender_restrictions=
        -o smtpd_recipient_restrictions=permit_mynetworks,reject
        -o mynetworks=127.0.0.0/8
        -o smtpd_authorized_xforward_hosts=127.0.0.0/8
    
    # re-inject mails from decency for bouncing
    # this is only required if you use virus or spam filters with bouncing
    127.0.0.1:10260	inet	n	-	-	-	-	smtpd
        -o content_filter=decency-bounce
        -o receive_override_options=no_unknown_recipient_checks,no_header_body_checks,no_milters
        -o smtpd_helo_restrictions=
        -o smtpd_client_restrictions=
        -o smtpd_sender_restrictions=
        -o smtpd_recipient_restrictions=permit_mynetworks,reject
        -o mynetworks=127.0.0.0/8
        -o smtpd_authorized_xforward_hosts=127.0.0.0/8

=head2 main.cf

There are two possible ways you can include this content filter into postfix. The first is via content_filter, the second via check_*_access, eg check_client_access.

=over

=item * content_filter

The advantage: it is easy. The disadvantage: all mails (incoming, outgoing) will be filtered. In a one-mailserver-for-all configuration this might be ugly.

    # main.cf
    content_filter = decency:127.0.0.1:12345

=item * Via check_*_access

And example using pcre on all mails would be:

    # main.cf
    smtpd_client_restrictions =
        check_client_access = pcre:/etc/postfix/decency-filter, reject

Then in the /etc/postfix/decency-filter file:

    # /path/to/access
    /./ FILTER decency:127.0.0.1:12345


=head1 CONFIG

Provide either a hashref or a YAML file. 

Example:

    ---
    
    # enable log to syslog
    enable_syslog: 1
    
    # enable log to STDERR (for forground mode)
    enable_warn: 1
    
    # log output level .. 0 to 5
    log_level: 20
    
    # directory for saving mails temporarily while filtering
    spool_dir: /tmp/deceny-filter-spool
    
    
    # if the content filter does not use the same cache as the policy does
    #   and you use foward_scoring, then you should set a keyword which
    #   proves that the header originates from the policy server and is not
    #   injected by a spammer!
    policy_verify_key: /etc/decency/sign.pub
    
    # this enables receival of scoring results from the policy server
    accept_scoring: 1
    
    # how to handle spam (if you use spam modules)
    spam:
        
        # there are three:
        #   scoring = check through all scoring capable modules, account, decide
        #   strict = first module find anything wrong triggers handling
        #   ignore = dont do anything, just run the modules (for debugging)
        behavior: scoring
        
        # if behavior is scoring: amount of score to consider the mail as spam
        threshold: -150
        
        # if spam (scoring+score>threshold or strict), what to do
        #   tag = tag mail (X-Decency) as spam
        #   bounce = send back to sender (BACKSCATTER! NOT A GOOD IDEA)
        #   delete = silently remove (for the hardcore haters)
        handle: bounce
        
        # only for handle = tag, prefix for the subject of spam mails 
        #spam_subject_prefix:
    
    # how to handle virus mails (if you use antivirus modules)
    virus:
        # what to do with virus mails?
        #   bounce = send back (without virus!) to sender
        #   delete = remove mail permanently
        #   quarantine = move into quarantine directory (below)
        #   ignore = don't do anything (for debugging)
        handle: bounce
        
        # wheter send a notification to the recipient or not. 
        #   does not work with handle = ignore (of course)
        notify: 0
    
    
    database:
        type: dbi
        args:
            - 'dbi:SQLite:dbname=/tmp/decency.db'
    
    cache:
        class: File
        cache_root: /tmp/decency-cache
    
    # all the content filters to use
    #   the order they are provided here will be the order
    #   they are applied
    #   so you might want to put virus filters in the front, then
    #   spam filters, then any possible manipulation filters
    filters:
    
                                         

=head1 CLASS ATTRIBUTES


=head2 spool_dir

The directory where to save received mails before filtering

=cut

has spool_dir => ( is => 'rw', isa => 'Str' );

=head2 temp_dir

Holds temp files for modules

=cut

has temp_dir => ( is => 'rw', isa => 'Str' );

=head2 queue_dir

Holds queued mails (currently working on)

=cut

has queue_dir => ( is => 'rw', isa => 'Str' );

=head2 mime_output_dir

Directory for temporary mime output .. required by MIME::Parser

Defaults to spool_dir/mime

=cut

has mime_output_dir => ( is => 'rw', isa => 'Str' );

=head2 reinject_failure_dir

Directory for reinjection failures

Defaults to spool_dir/failure

=cut

has reinject_failure_dir => ( is => 'rw', isa => 'Str' );

=head2 quarantine_dir

Directory for quarantined mails (virus, spam)

Defaults to spool_dir/quarantine

=cut

has quarantine_dir => ( is => 'rw', isa => 'Str' );

=head2 spam_*

There is either spam scoring, strict or keep.

Keep account on positive or negative score per file. Each filter module may increment or decrement score on handling the file. The overall score determines in the end wheter to bounce or re-inject the mail.

=cut

has spam_behavior           => ( is => 'rw', isa => 'Str', default => 'ignore' );
has spam_handle             => ( is => 'rw', isa => 'Str', default => 'tag' );
has spam_subject_prefix     => ( is => 'rw', isa => 'Str', predicate => 'has_spam_subject_prefix' );
has spam_threshold          => ( is => 'rw', isa => 'Int', default => -100 );
has spam_notify_recipient   => ( is => 'rw', isa => 'Bool', default => 0 );
has spam_recipient_template => ( is => 'rw', isa => 'Str' );
has spam_recipient_subject  => ( is => 'rw', isa => 'Str', default => 'Spam detected' );
has spam_noisy_headers      => ( is => 'rw', isa => 'Bool', default => 0 );

=head2 virus_*

Virus handling

=cut

has virus_handle             => ( is => 'rw', isa => 'Str', default => 'ignore' );
has virus_notify_recipient   => ( is => 'rw', isa => 'Bool', default => 0 );
has virus_recipient_template => ( is => 'rw', isa => 'Str' );
has virus_recipient_subject  => ( is => 'rw', isa => 'Str', default => 'Virus detected' );
has virus_notify_sender      => ( is => 'rw', isa => 'Bool', default => 0 );
has virus_sender_template    => ( is => 'rw', isa => 'Str' );
has virus_sender_subejct     => ( is => 'rw', isa => 'Str', default => 'Virus detected' );


=head2 policy_verify_key

=cut

has accept_scoring => ( is => 'rw', isa => 'Bool', default => 0 );
has policy_verify_key => ( is => 'rw', isa => 'Str', predicate => 'has_policy_verify_key', trigger => sub {
    my ( $self, $key_file ) = @_;
    
    # check file
    $key_file = $self->config_dir . "/$key_file"
        if $self->has_config_dir && ! -f $key_file;
    die "Could not access policy_verify_key key file '$key_file'\n"
        unless -f $key_file;
    
    # read key
    open my $fh, '<', $key_file
        or die "Cannot open policy_verify_key key file for read: $!\n";
    my $key_content = join( "", <$fh> );
    close $fh;
    
    # store key
    $self->policy_verify_key_rsa( Crypt::OpenSSL::RSA->new_public_key( $key_content ) );
    $self->logger->info( "Setup verify key '$key_file'" );
    
    return;
} );
has policy_verify_key_rsa => ( is => 'rw', isa => 'Crypt::OpenSSL::RSA' );


=head2 session_data

SessionItem (L<Mail::Decency::Core::SessionItem::ContentFilter>) of the current handle file

=cut

has session_data => ( is => 'rw', isa => 'Mail::Decency::Core::SessionItem::ContentFilter' );



=head1 METHODS

=head2 init

INit cache, database, logger, dirs and content filter

=cut

sub init {
    my ( $self ) = @_;
    
    
    
    # mark es inited
    $self->{ inited } ++;
    
    $self->init_logger();
    $self->init_cache();
    $self->init_database();
    $self->init_dirs();
    $self->init_content_filters();
    
    # having scoring ?
    if ( defined( my $virus_ref = $self->config->{ virus } ) && ref( $self->config->{ virus } ) ) {
        
        # what's the basic behavior ?
        die "behavior has to be set to 'ignore', 'scoring' or 'strict' in spam section\n"
            unless $virus_ref->{ handle }
            && $virus_ref->{ handle } =~ /^(?:bounce|delete|quarantine|ignore)$/
        ;
        $self->virus_handle( $virus_ref->{ handle } );
        
        # for bounce mode ..
        if ( $self->virus_handle =~ /^(?:bounce|delete|quarantine)$/ ) {
            
            # check for each direction ..
            foreach my $direction( qw/ sender recipient / ) {
                next if $direction eq 'sender' && $self->virus_handle eq 'bounce';
                
                # determine methods and parameter names
                my $template = "${direction}_template"; # sender_template
                my $template_meth = "virus_$template";  # virus_sender_template
                my $enable = "notify_${direction}";     # notify_sender
                my $enable_meth = "virus_$enable";      # virus_notify_sender
                
                # is enabled ?
                $self->$enable_meth( 1 )
                    if $virus_ref->{ $enable };
                
                # having custom template ?
                if ( $self->$enable_meth() && $virus_ref->{ $template } ) {
                    my $filename = -f $virus_ref->{ $template }
                        ? $virus_ref->{ $template }
                        : $self->config_dir. "/$virus_ref->{ $template }"
                    ;
                    die "Cant read from virus $template file '$filename'\n"
                        unless -f $filename;
                    
                    # template
                    $self->$template_meth( $filename );
                    
                    # subject
                    my $subject = "${direction}_subject";
                    my $subject_meth = "virus_${subject}";
                    $self->$subject_meth( $virus_ref->{ $subject } )
                        if $virus_ref->{ $subject }
                }
            }
        }
    }
    else {
        $self->virus_handle( 'ignore' );
    }
    
    # having spam things ?
    if ( defined( my $spam_ref = $self->config->{ spam } ) && ref( $self->config->{ spam } ) ) {
        
        # what's the basic behavior ?
        die "behavior has to be set to 'ignore', 'scoring' or 'strict' in spam section\n"
            unless $spam_ref->{ behavior }
            && $spam_ref->{ behavior } =~ /^(?:scoring|strict|ignore)$/
        ;
        $self->spam_behavior( $spam_ref->{ behavior } );
        
        
        # how to handle recognized spam ?
        unless ( $self->spam_behavior eq 'ignore' ) {
            die "spam_handle has to be set to 'tag', 'bounce' or 'delete' in scoring!\n"
                unless $spam_ref->{ handle }
                && $spam_ref->{ handle } =~ /^(?:tag|bounce|delete)$/
            ;
            $self->spam_handle( $spam_ref->{ handle } );
            
            # any spam subject prefix ?
            $self->spam_subject_prefix( $spam_ref->{ spam_subject_prefix } )
                if $self->spam_handle eq 'tag' && $spam_ref->{ spam_subject_prefix };
            
            # wheter use noisy headers or not
            $self->spam_noisy_headers( $spam_ref->{ noisy_headers } || 0 );
            
            # set threshold
            if ( $self->spam_behavior eq 'scoring' ) {
                die "Require threshold in spam section with behavior = scoring\n"
                    unless defined $spam_ref->{ threshold };
                $self->spam_threshold( $spam_ref->{ threshold } );
            }
            
            # enable notification of recipient on bounce or delete ?
            if ( ( $self->spam_handle eq 'bounce' || $self->spam_handle eq 'delete' ) && $spam_ref->{ notify_recipient } ) {
                $self->spam_notify_recipient( 1 );
                
                # having a template for those notifications ?
                if ( $spam_ref->{ recipient_template } ) {
                    die "Cannot read from spam recipient_template file '$spam_ref->{ recipient_template }'\n"
                        unless -f $spam_ref->{ recipient_template };
                    $self->spam_recipient_template( $spam_ref->{ recipient_template } );
                }
            }
        }
    }
    else {
        $self->spam_behavior( 'ignore' );
    }
    
    # accept scoring from headers ?
    if ( $self->config->{ accept_scoring } ) {
        $self->accept_scoring( 1 );
        
        # having verify key ?
        if ( $self->config->{ policy_verify_key } ) {
            $self->policy_verify_key( $self->config->{ policy_verify_key } );
        }
        
        # hmm, this is not good -> warn
        else {
            $self->logger->error( "Warning: You accept scoring from external policy servers, but don't use a verification key! Spammers can inject positive scoring!" );
        }
    }
    
    return;
}


=head2 init_dirs

Inits the queue, checks spool dir for existing files -> read them

=cut

sub init_dirs {
    my ( $self ) = @_;
    
    # check and set spool dir
    die "Require 'spool_dir' in config (path to directory where saving mails while filtering)\n"
        unless $self->config->{ spool_dir };
    make_path( $self->config->{ spool_dir }, { mode => 0700 } )
        unless -d $self->config->{ spool_dir };
    die "Require 'spool_dir'. '". $self->config->{ spool_dir }. "' is not a directory. Please create it!\n"
        unless -d $self->config->{ spool_dir };
    $self->spool_dir( $self->config->{ spool_dir } );
    
    # make sub dirs
    my %dirs = qw(
        temp_dir                temp
        queue_dir               queue
        mime_output_dir         mime
        reinject_failure_dir    failure
        quarantine_dir          quarantine
    );
    while( my( $name, $dir ) = each %dirs ) {
        $self->config->{ $name } ||= $self->spool_dir. "/$dir";
        make_path( $self->config->{ $name }, { mode => 0700 } )
            unless -d $self->config->{ $name };
        die "Could not non existing '$name' dir '". $self->config->{ $name }. "'. Please create yourself.\n"
            unless -d $self->config->{ $name };
        $self->$name( $self->config->{ $name } );
        $self->logger->debug2( "Set '$name'-dir to '". $self->$name. "'" );
    }
    
    return ;
}


=head2 init_content_filters

Reads all content filters, creates instance and add to list of filters

=cut

sub init_content_filters {
    my ( $self ) = @_;
    
    # check config
    die "'filters' has to be an Array!\n"
        if $self->config->{ filters }
        && ! ref( $self->config->{ filters } ) eq 'ARRAY';
    
    # get weak ref instance of self
    weaken( my $self_weak = $self );
    
    
    foreach my $filter_ref( @{ $self->config->{ filters } } ) {
        
        # get name anf config
        my ( $name, $config_ref ) = %$filter_ref;
        
        # setup enw filter
        
        my $filter = $self->gen_child(
            "Mail::Decency::ContentFilter" => $name => $config_ref );
        $filter_ref->{ $name } = $filter->config if $filter;
    }
    
}


=head2 start

Starts all POE servers without calling the POE::Kernel->run

=cut

sub start {
    my ( $self ) = @_;
    
    # we need a handle for ourselfs
    weaken( my $self_weak = $self );
    
    # start forking server
    Mail::Decency::Core::POEForking::SMTP->new( $self, {
        temp_mask => $self->spool_dir. "/mail-XXXXXX"
    } );
    
}


=head2 run 

Start and run the server via POE::Kernel->run

=cut

sub run {
    my ( $self ) = @_;
    $self->start();
    POE::Kernel->run;
}


=head2 train

=cut

sub train {
    my ( $self, $args_ref ) = @_;
    
    # get cmd method
    my $train_cmd = $args_ref->{ spam }
        ? 'cmd_learn_spam'
        : 'cmd_learn_ham'
    ;
    
    # determine all modules being trainable
    my @trainable = grep {
        $_->isa( 'Mail::Decency::ContentFilter::Core::Spam' )
        && $_->can( $train_cmd )
        && ! $_->config->{ disable_train }
    } @{ $self->childs };
    die "No trainable modules enabled\n"
        unless @trainable;
    
    # strip cmd_
    $train_cmd =~ s/^cmd_//;
    
    # having move ?
    if ( $args_ref->{ move } ) {
        die "Move directory '$args_ref->{ move }' does not exist?\n"
            unless -d $args_ref->{ move };
        $args_ref->{ move } =~ s#\/+$##;
    }
    
    # get all files for training
    my @files = -d $args_ref->{ files }
        ? glob( "$args_ref->{ files }/*" )
        : glob( $args_ref->{ files } )
    ;
    die "No mails for training found for '$args_ref->{ files }'"
        unless @files;
    
    # begin training
    my ( %trained, %not_required, %errors ) = ();
    print "Will train ". ( scalar @files ). " messages as ". ( $args_ref->{ spam } ? 'SPAM' : 'HAM' ). "\n";
    
    my $start_ref = [ gettimeofday() ];
    
    my $counter = 0;
    my $amount  = scalar @files;
    foreach my $file( @files ) {
        print "". ( ++$counter ). " / $amount: '$file'\n";
        
        my ( $th, $tn ) = tempfile( $self->temp_dir. "/train-XXXXXX", UNLINK => 0 );
        close $th;
        copy( $file, $tn );
        my $size = -s $tn;
        $self->session_init( $tn, $size );
        
        foreach my $module( @trainable ) {
            
            # check wheter mail is spam or not
            $self->session_data->spam_score( 0 );
            eval {
                $module->handle;
            };
            
            # stop here, if ..
            if (
                
                # .. mail should be spam and is recognized as such
                ( $args_ref->{ spam } && $self->session_data->spam_score < 0 )
                
                # .. mail should NOT be spam and also not recognized as spam
                || ( $args_ref->{ ham } && $self->session_data->spam_score >= 0 ) 
            ) {
                print "  = $module / Already trained\n";
                $not_required{ "$module" }++;
                next;
            }
            
            # run filter with train command now
            my ( $res, $result, $exit_code );
            eval {
                ( $res, $result, $exit_code ) = $module->cmd_filter( $train_cmd );
            };
            my $error = $@;
            
            # having unexpected error
            if ( $error || ( $exit_code && $result ) ) {
                my $message = $error || $result;
                print "  * $module / Error\n*****\n$message\n*****\n\n";
                $errors{ "$module" }++;
            }
            
            # all ok -> trained
            else {
                print "  + $module / Success\n";
                $trained{ "$module" }++;
            }
        }
        unlink( $tn );
        unlink( "$tn.info" ) if -f "$tn.info";
        
        my $diff = tv_interval( $start_ref, [ gettimeofday() ] );
        printf "  > %.2f seconds remaining\n", ( ( $diff / $counter ) * $amount ) - $diff;
        
        if ( $args_ref->{ move } ) {
            ( my $target = $file ) =~ s#^.*\/##;
            $file = abs_path( $file );
            $target = abs_path( "$args_ref->{ move }/$target" );
            move( $file, $target );
            die "Oops, cannot move '$file' -> '$target'\n" unless -f $target;
        }
        elsif ( $args_ref->{ remove } ) {
            unlink( $file );
        }
    }
    
    # print out skipped (ham/spam)
    if ( scalar keys %not_required ) { 
        print "\n**** Not Required ****\n";
        foreach my $name( sort keys %not_required ) {
            print "$name: $not_required{ $name }\n";
        }
    }
    
    # print out trained (ham/spam)
    if ( scalar keys %trained ) { 
        print "\n**** Trained ****\n";
        foreach my $name( sort keys %trained ) {
            print "$name: $trained{ $name }\n";
        }
    }
    else {
        print "\n**** None trained ****\n";
    }
    
    # print out errors (ham/spam)
    if ( scalar keys %errors ) {
        print "\n**** Errors ****\n";
        foreach my $name( sort keys %errors ) {
            print "$name: $errors{ $name }\n";
        }
    }
    else {
        print "\n**** No Errors ****\n";
    }
}



=head2 get_handlers

=cut

sub get_handlers {
    my ( $self ) = @_;
    
    weaken( my $self_weak = $self );
    
    # { file => '/path/to/file', from => "from@domain.tld", to => "to@domain.tld" }
    return sub {
        my ( $ref ) = @_;
        
        $self_weak->logger->debug3( "Handle new: $ref->{ file }, from: $ref->{ from }, to: $ref->{ to }" );
        
        my ( $ok, $message );
        
        # better eval that.. the server shold NOT die .
        eval {
            
            # write the from, to, size and such to yaml file
            open my $fh, ">", $ref->{ file }. ".info"
                or die "Cannot open '$ref->{ file }' for read\n";
            
            print $fh YAML::Dump( $ref );
            close $fh;
            
            ( $ok, $message ) = $self_weak->handle( $ref->{ file }, -s $ref->{ file } );
        };
        
        # log out error
        if ( $@ ) {
            $self_weak->logger->error( "Error handling '$ref->{ file }': $@" );
        }
        
        return ( $ok, $message );
    }
    
}


=head2 handle

Calls the handle method of all registered filters.

Will be called from the job queue

=cut

sub handle {
    my ( $self, $file, $size ) = @_;
    
    # setup mail info (mime, from, to and such)
    eval {
        $self->session_init( $file, $size );
    };
    if ( $@ ) {
        $self->logger->error( "Cannot init session: $@" );
        return;
    }
    
    # handle by all filters
    my $status = 'ok';
    
    EACH_FILTER:
    foreach my $filter( @{ $self->childs } ) {
        $self->logger->debug3( "Handle to '$filter'" );
        
        # determine weight before, so we can increment stats
        my $weight_before  = $self->session_data->spam_score;
        my $start_time_ref = [ gettimeofday() ];
        
        eval {
            
            # set alarm if timeout enabed
            my $alarm = \( local $SIG{ ALRM } );
            if ( $filter->timeout ) {
                $$alarm = sub {
                    Mail::Decency::Core::Exception::Timeout->throw( { message => "Timeout" } );
                };
                alarm( $filter->timeout + 1 );
            }
            
            # check size.. if to big for filter -> don't handle
            if ( $filter->can( 'max_size' )
                && $filter->max_size
                && $self->session_data->file_size > $filter->max_size
            ) {
                Mail::Decency::Core::Exception::FileToBig->throw( { message => "File to big" } );
            }
            
            # run the filter on the current file
            else {
                $filter->handle();
            }
        };
        my $err = $@;
        
        # reset alarm
        alarm( 0 ) if $filter->timeout;
        
        
        #
        # STATI AFTER ERROR:
        #   ok: mail is OK -> pass to next module
        #   spam: mail is finally recognized as spam. Stop handling. Finish as spam.
        #   virus: mail is infected by a virus. Stop handling. Finish as virus.
        #   drop: mail is to be dropped. No further handling. 
        # 
        
        if ( $err ) {
            
            given ( $err ) {
                
                # got final SPAM
                when( blessed( $_ ) && $_->isa( 'Mail::Decency::Core::Exception::Spam' ) ) {
                    $self->session_data->add_spam_details( $_->message );
                    $self->logger->debug0( "Mail is spam after $filter, message: ". $_->message );
                    $status = 'spam';
                }
                
                # got final VIRUS
                when( blessed( $_ ) && $_->isa( 'Mail::Decency::Core::Exception::Virus' ) ) {
                    $self->session_data->add_spam_details( $_->message );
                    $self->logger->debug0( "Mail is virus after $filter, message: ". $_->message );
                    $status = 'virus';
                }
                
                # error: timeout
                when( blessed( $_ ) && $_->isa( 'Mail::Decency::Core::Exception::Drop' ) ) {
                    $self->logger->debug0( "Dropping mail after $filter" );
                    $status = 'drop';
                }
                
                # file to big, ignore, log
                when( blessed( $_ ) && $_->isa( 'Mail::Decency::Core::Exception::FileToBig' ) ) {
                    $self->logger->debug0( "File to big for $filter" );
                }
                
                # error: timeout
                when( blessed( $_ ) && $_->isa( 'Mail::Decency::Core::Exception::Timeout' ) ) {
                    $self->logger->error( "Timeout in $filter" );
                }
                
                # got some unknown error
                default {
                    $self->logger->error( "Error in $filter: $_" );
                }
            }
        }
        
        # update stats
        if ( $self->enable_stats ) {
            my $weight_diff = $self->session_data->spam_score - $weight_before;
            $self->update_stats( $filter => uc( $status ) => $weight_diff, tv_interval( $start_time_ref, [ gettimeofday() ] ) );
            $self->logger->debug2( "Added $weight_diff ($filter)" );
        }
        
        last EACH_FILTER if $status ne 'ok';
    }
    
    # write mail info to caches
    $self->session_write_cache;
    
    # final code ..
    my $final_code = CF_FINAL_OK;
    
    # having finish hooks ?
    foreach my $filter( @{ $self->childs } ) {
        next unless $filter->can( 'hook_pre_finish' );
        eval {
            ( $status, $final_code ) = $filter->hook_pre_finish( $status );
        };
        $self->logger->error( "Error in pre finsh hook for '$filter': $@" ) if $@;
    }
    
    # found virus ? take care of it!
    if ( $status eq 'virus' ) {
        $final_code = $self->finish_virus;
    }
    
    # recognized spam ? see to it.
    elsif ( $status eq 'spam' ) {
        $final_code = $self->finish_spam;
    }
    
    # ok, all ok -> regular finish
    elsif ( $status ne 'drop' ) {
        $final_code = $self->finish_ok;
    }
    
    # having after-finish hooks ?
    foreach my $filter( @{ $self->childs } ) {
        next unless $filter->can( 'hook_post_finish' );
        eval {
            ( $status, $final_code ) = $filter->hook_post_finish( $status );
        };
        $self->logger->error( "Error in post finsh hook for '$filter': $@" ) if $@;
    }
    
    
    # clear all
    my $spam_details = join( " / ", @{ $self->session_data->spam_details } );
    $self->session_data->cleanup;
    
    # return the final code to the SMTP server, which will then either force the mta
    #   (postfix) to bounce the mail by rejecting it or accept, to 
    if ( $final_code == CF_FINAL_OK || $final_code == CF_FINAL_DELETED ) {
        return ( 1 );
    }
    else {
        return ( 0, $spam_details );
    }
}


=head2 finish_spam

Got a spam mail -> handle it as spam. Either bounce, tag or delete

=over

=item * delete

With this handle, the mail will be removed. A notification might be send to the recipient.

=item * bounce

The mail is bounced back to the sender.

=back

=cut

sub finish_spam {
    my ( $self ) = @_;
    
    my $session = $self->session_data;
    my $score   = $session->spam_score;
    my @info    = @{ $session->spam_details };
    
    # just remove and ignore
    if ( $self->spam_handle eq 'delete' ) {
        $self->logger->info( sprintf( 'Delete spam mail from %s to %s, size %d with score %d',
            $session->from, $session->to, $session->file_size, $score ) );
        return CF_FINAL_DELETED;
    }
    
    # do bounce mail
    elsif ( $self->spam_handle eq 'bounce' ) {
        $self->logger->info( sprintf( 'Bounce spam mail from %s to %s, size %d with score %d',
            $session->from, $session->to, $session->file_size, $score ) );
        
        return CF_FINAL_BOUNCE;
    }
    
    # do ignore mail, don't tag, do nothing like this
    elsif ( $self->spam_handle eq 'ignore' ) {
        return $self->reinject;
    }
    
    # do tag mail
    else {
        my $header = $self->session_data->mime->head;
        
        # prefix subject ?
        if ( $self->has_spam_subject_prefix ) {
            my $subject = $header->get( 'Subject' ) || '';
            ( my $prefix = $self->spam_subject_prefix ) =~ s/ $//;
            $header->replace( 'Subject' => "$prefix $subject" );
        }
        
        # add tag
        $header->replace( 'X-Decency-Result'   => 'SPAM' );
        $header->replace( 'X-Decency-Score'    => $score );
        $header->replace( 'X-Decency-SpamInfo' => join( " | ", @info ) )
            if $self->spam_noisy_headers;
        
        # update mime
        $self->session_data->write_mime;
        
        # reinject
        return $self->reinject;
    }
}


=head2 finish_virus

Reinject mail into mailserver

=cut

sub finish_virus {
    my ( $self ) = @_;
    
    # get session..
    my $session = $self->session_data;
    
    # don't do that .. however, here is the bounce
    if ( $self->virus_handle eq 'bounce' ) {
        $self->logger->info( sprintf( 'Bounce virus infected mail from %s to %s, size %d with virus "%s"',
            $session->from, $session->to, $session->file_size, $session->virus ) );
        return CF_FINAL_BOUNCE;
    }
    
    # don't do that .. however, here is the bounce
    elsif ( $self->virus_handle eq 'delete' ) {
        $self->logger->info( sprintf( 'Delete virus infected mail from %s to %s, size %d with virus "%s"',
            $session->from, $session->to, $session->file_size, $session->virus ) );
        return CF_FINAL_DELETED;
    }
    
    # inject mail into qurantine dir
    elsif ( $self->virus_handle eq 'quarantine' ) {
        $self->logger->info( sprintf( 'Quarantine virus infected mail from %s to %s, size %d with virus "%s"',
            $session->from, $session->to, $session->file_size, $session->virus ) );
        $self->_save_mail_to_dir( 'quarantine_dir' );
        return CF_FINAL_DELETED;
    }
    
    # don't do that .. 
    else {
        $self->logger->info( sprintf( 'Delivering virus infected mail from %s to %s, size %d with virus "%s"',
            $session->from, $session->to, $session->file_size, $session->virus ) );
        return $self->reinject;
    }
    
}


=head2 finish_ok

Reinject mail into mailserver

=cut

sub finish_ok {
    my ( $self ) = @_;
    
    # being noisy -> set spam info even if not spam
    if ( $self->spam_noisy_headers ) {
        my $header = $self->session_data->mime->head;
        $header->replace( 'X-Decency-Result'  => 'GOOD' );
        $header->replace( 'X-Decency-Score'   => $self->session_data->spam_score );
        $header->replace( 'X-Decency-Details' => join( " | ",
            @{ $self->session_data->spam_details } ) );
        
        # update mime
        $self->session_data->write_mime;
    }
    
    return $self->reinject;
}


=head2 reinject

Reinject mails to postfix queue, or archive in send-queue

=cut

sub reinject {
    my ( $self, $type ) = @_;
    
    my $reinject_ref = $self->config->{ reinject };
    
    eval {
        
        my $smtp = Net::SMTP->new(
            $reinject_ref->{ host }. ":". $reinject_ref->{ port },
            Hello   => 'decency',
            Timeout => 30,
            #Debug  => 1,
        ) or die "ARR: $!";
        
        $smtp->hello( 'localhost' );
        $smtp->mail( $self->session_data->from );
        $smtp->to( $self->session_data->to );
        $smtp->data;
        
        # parse file and print all lines
        open my $fh, '<', $self->session_data->file;
        while ( my $l = <$fh> ) {
            chomp $l;
            $smtp->datasend( $l. CRLF ) or die $!;
        }
        
        # end data
        $smtp->dataend;
        
        # get reponse message containg new ID
        my $message = $smtp->message;
        
        # quit connection
        $smtp->quit;
        
        # determine message
        if ( $message && $message =~ /queued as ([A-Z0-9]+)/ ) {
            $self->logger->debug0( "Reinjected mail as $1" );
            $self->session_data->next_id( $1 );
            $self->session_write_cache;
        }
        else {
            Mail::Decency::Core::Exception::ReinjectFailure->throw( { message => "Could not reinject" } );
        }
    };
    
    return CF_FINAL_OK unless $@;
    
    given ( $@ ) {
        
        # reinect failure -> save to failure dir and log
        when( blessed( $_ ) && $_->isa( 'Mail::Decency::Core::Exception::ReinjectFailure' ) ) {
            $self->logger->error( "Could not retreive reinjection ID - possible error on reinjection ? Reinject manual." );
            $self->_save_mail_to_dir( 'reinject_failure_dir' );
        }
        
        # some other error..
        default {
            $self->logger->error( "Could not reinject mail: $@" );
        }
    }
    
    return CF_FINAL_ERROR;
}



=head2 send_notify

Encapses a mime mail with either virus or spam template. 

=cut

sub send_notify {
    my ( $self, $type, $direction, $to ) = @_;
    my $mime = $self->session_data->mime;
    
    eval {
        
        # build the multipart surrounding
        my $subject_method = "${type}_${direction}_subject";
        my $encaps = MIME::Entity->build(
            Subject    => $self->$subject_method || uc( $type ). " notification",
            From       => $self->notification_from,
            To         => $to,
            Type       => 'multipart/mixed',
            'X-Mailer' => 'Decency'
        );
        
        my @data = ();
        my $template_meth = "${type}_${direction}_template"; # eg spam_recipient_template
        
        # get session
        my $session = $self->session_data;
        
        # having a custom template ..
        if ( defined $self->$template_meth ) {
            
            # read template ..
            open my $fh, '<', $self->$template_meth
                or die "Cannot open '". $self->$template_meth. "' for read: $!\n";
            
            # add reason of rejection
            my %template_vars = ( reason => $type );
            
            # add virus name
            $template_vars{ virus } = $session->virus if $type eq 'virus';
            
            # add from, to
            $template_vars{ $_ } = $session->$_ for qw/ from to /;
            
            # add subject, if any
            $template_vars{ subject } = $session->mime->head->get( 'Subject' ) || "(no subject)";
            
            # read and parse template
            @data = map {
                chomp;
                s/<%\s*([^%]+)\s*%>/defined $template_vars{ $1 } ? $template_vars{ $1 } : $1/egms;
                $_;
            } <$fh>;
            
            # close template
            close $fh;
        }
        else {
            push @data, "Your mail to ". $session->to. " has been rejected.";
            push @data, "";
            push @data, "Subject of the mail: ". ( $session->mime->head->get( 'Subject' ) || "(no subject)" );
            push @data, "";
            push @data, "Reason: categorized as ". $type. ( $type eq 'virus' ? " (". $session->virus. ")" : "" );
        }
        
        # add the template 
        $encaps->add_part( MIME::Entity->build(
            Type     => 'text/plain',
            Encoding => 'quoted-printable',
            Data     => \@data
        ) );
        
        unless ( $self->reinject( $encaps ) == CF_FINAL_OK ) {
            die "Error sending $type $direction notification mail to $to\n";
        }
    };
    
    # having error ?
    if ( $@ ) {
        $self->logger->error( "Error in mime encapsulation: $@" );
        return 0;
    }
    
    return 1;
}






=head2 session_init

Returns hashref of info's about a mail (file) .. containgin original "MAIL FROM" (from), "RCPT TO" (to), if anyone requires the pre-encoded mime, then also mime object

=cut

sub session_init {
    my ( $self, $file, $size ) = @_;
    
    # setup new info
    ( my $init_id = $file ) =~ s/[\/\\]/-/g;
    $self->session_data( Mail::Decency::Core::SessionItem::ContentFilter->new(
        id              => $init_id || "unknown-". time(),
        file            => $file,
        mime_output_dir => $self->mime_output_dir,
        cache           => $self->cache
    ) );
    my $session = $self->session_data;
    
    
    #
    # RETREIVE QUEUE ID, UPDATE FROM CONTENT FILTER CACHE
    #
    
    # get last queue ID
    my @received = $session->mime->head->get( 'Received' );
    $self->logger->debug0( "received ". Dumper( \@received ) );
    my $received = shift @received;
    if ( $received && $received =~ /E?SMTP id ([A-Z0-9]+)/ms ) {
        my $id = $1;
        $session->id( $id );
        
        # try read info from policy server from cache
        my $cached = $self->cache->get( "QUEUE-$id" );
        $self->logger->debug2( "Got cached $id ". Dumper( $cached ) );
        $session->update_from_cache( $cached )
            if $cached && ref( $cached );
    }
    
    # oops, this should not happen, maybe in debug cases, if mails
    #   are directyly injected into the content filter ?!
    else {
        $self->logger->error( "Could not determine Queue ID! No 'Received' header found! Postfix should set this!" );
    }
    
    # retreive scoring from policy server, if any
    $session->retreive_policy_scoring( $self->accept_scoring );
    
    
    return $session;
}


=head2 session_write_cache

Write mail info to caches

=cut

sub session_write_cache {
    my ( $self ) = @_;
    
    # get session to be cached
    my $session_ref = $self->session_data->for_cache;
    
    # save to cache (max 10min..)
    $self->cache->set( "QUEUE-$session_ref->{ queue_id }", $session_ref, time() + 600 );
    
    # write next to cache
    if ( $session_ref->{ next_id } ) {
        my %next = %{ $session_ref };
        $next{ queue_id } = $session_ref->{ next_id };
        $next{ prev_id }  = $session_ref->{ queue_id };
        $next{ next_id }  = undef;
        $self->cache->set( "QUEUE-$next{ queue_id }", \%next, time() + 600 );
        
        $self->logger->debug3( "Store next id $session_ref->{ next_id } for $session_ref->{ queue_id }" );
    }
    
    # re-write prev to cache (keep alive)
    if ( $session_ref->{ prev_id } ) {
        
        # get cached prev
        my $prev_cached = $self->cache->get( "QUEUE-$session_ref->{ prev_id }" );
        
        # create new prev
        my %prev = %{ $session_ref };
        $prev{ queue_id } = $session_ref->{ prev_id };
        $prev{ prev_id }  = $prev_cached ? $prev_cached->{ prev_id } : undef;
        $prev{ next_id }  = $session_ref->{ queue_id };
        $self->cache->set( "QUEUE-$prev{ queue_id }", \%prev, time() + 600 );
        $self->logger( debug3 => "Store prev id $session_ref->{ prev_id } for $session_ref->{ id }" );
    }
    
    return ;
}




#
#       SPAM
#





=head2 add_spam_score

Add score to global counter for current filter queue

=cut

sub add_spam_score {
    my ( $self, $weight, $module, $message_ref ) = @_;
    
    # get info
    my $session = $self->session_data;
    
    # add score
    $session->add_spam_score( $weight );
    
    # add info
    $message_ref ||= [];
    $message_ref = [ $message_ref ] unless ref( $message_ref );
    $session->add_spam_details( join( "; ",
        "Module: $module",
        "Score: $weight",
        @$message_ref
    ) );
    
    # provide result based on config settings
    if ( (
            # strict hit
            $session->spam_score < 0
            && $self->spam_behavior eq 'strict'
        )
        || (
            # threshold hit
            $self->spam_behavior eq 'scoring'
            && $session->spam_score <= $self->spam_threshold
    ) ) {
        # throw ..
        Mail::Decency::Core::Exception::Spam->throw( { message => "Spam found" } );
    }
}


=head2 virus_info

Call found a virus from module

=cut

sub found_virus {
    my ( $self, $info ) = @_;
    $self->session_data->virus( $info );
    
    # throw final exception
    Mail::Decency::Core::Exception::Virus->throw( { message => "Virus found: $info" } );
}


=head2 _save_mail_to_dir

Save a mail to some dir. Called from quarantine or reinjection failures

=cut

sub _save_mail_to_dir {
    my ( $self, $dir_name ) = @_;
    
    # determine from with replaced @
    ( my $from = $self->from || "unkown" ) =~ s/\@/-at-/;
    
    # determine to with replaced @
    ( my $to = $self->to || "unkown" ) =~ s/\@/-at-/;
    
    # format file <time>-<from>-<to> and replace possible problematic chars
    ( my $from_to = time(). "_FROM_${from}_TO_${to}" ) =~ s/[^\p{L}\d\-_\.]//gms;
    
    # get tempfile (assures uniqueness)
    my ( $th, $failure_file )
        = tempfile( $self->$dir_name. "/$from_to-XXXXXX", UNLINK => 0 );
    close $th;
    
    # copy file to archive folder
    copy( $self->file, $failure_file );
}

=head1 AUTHOR

Ulrich Kautz <uk@fortrabbit.de>

=head1 COPYRIGHT

Copyright (c) 2010 the L</AUTHOR> as listed above

=head1 LICENCSE

This library is free software and may be distributed under the same terms as perl itself.

=cut


1;
