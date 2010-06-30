package Mail::Decency::ContentFilter::Core::Cmd;

use Moose;
extends 'Mail::Decency::ContentFilter::Core';

use version 0.74; our $VERSION = qv( "v0.1.4" );

use mro 'c3';
use Data::Dumper;
use IO::Pipe;
use File::Temp qw/ tempfile /;

=head1 NAME

Mail::Decency::ContentFilter::Core::Cmd

=head1 DESCRIPTION

Base class for all command line filters. Including spam filter such as DSPAM and so on

=head1 CLASS ATTRIBUTES

=head2 cmd_check : Str

Check command.. normally the command which is used to filter a single mail. 

=cut

has cmd_check        => ( is => 'rw', isa => 'Str' );

=head2 cmd_learn_ham : Str

Learn HAM command..  

=cut

has cmd_learn_ham    => ( is => 'rw', isa => 'Str', predicate => 'can_learn_ham' );

=head2 cmd_learn_ham : Str

UNLearn HAM command.. (wrongly trained before)  

=cut

has cmd_unlearn_ham  => ( is => 'rw', isa => 'Str', predicate => 'can_unlearn_ham' );

=head2 cmd_learn_spam : Str

Learn new SPAM 

=cut

has cmd_learn_spam   => ( is => 'rw', isa => 'Str', predicate => 'can_learn_spam' );

=head2 cmd_unlearn_spam : Str

Unlearn wrongly trained SPAM 

=cut

has cmd_unlearn_spam => ( is => 'rw', isa => 'Str', predicate => 'can_learn_spam' );

=head2 cmd_user : Str

Command for tretreiving a user for the command line variable "%user%" 

=cut

has cmd_user         => ( is => 'rw', isa => 'Str', predicate => 'has_cmd_user' );

=head2 default_user : Str

User which will be used if none could be determined (if not set, the via "to" provided recipient will be used) 

=cut

has default_user     => ( is => 'rw', isa => 'Str', predicate => 'has_default_user' );

=head1 METHODS


=head2 pre_init

Add check params: cmd, check, train and untrain to list of check params

=cut

sub pre_init {
    my ( $self ) = @_;
    
    # init base, assure we get mime encoded
    $self->maybe::next::method();
    
    if ( $self->has_config_params ) {
        unshift @{ $self->{ config_params } ||=[] }, qw/
            cmd_check
            cmd_learn_ham
            cmd_unlearn_ham
            cmd_learn_spam
            cmd_unlearn_spam
            cmd_user
            default_user
        /;
    }
}



=head2 handle

Default handling for any content filter is getting info about the to be filterd file

=cut


sub handle {
    my ( $self ) = @_;
    
    # pipe file throught command
    my ( $res, $result, $exit_code ) = $self->cmd_filter;
    
    # return if cannot be handled
    return unless $res;
    
    # chomp lines
    1 while chomp $result;
    
    # handle result by the actual filter module
    return $self->handle_filter_result( $result, $exit_code );
}


=head2 cmd_filter

Pipes mail content through command line program and caches result

=cut

sub cmd_filter {
    my ( $self, $cmd_type ) = @_;
    $cmd_type ||= 'check';
    
    # retreive user
    my $user = $self->get_user();
    
    # build command
    my $cmd = $self->build_cmd( $cmd_type );
    
    # if command required user and no user could be determined -> abort
    if ( $cmd =~ /%user%/ && ! $user ) {
        $self->logger->error( "Could not determine user for recipient ". $self->to. ", abort" );
        return ( 0 );
    }
    
    # replace user in command
    $cmd =~ s/%user%/$user/g if $user;
    
    $self->logger->debug3( "Run cmd '$cmd'" );
    
    # we cannot redirect STDOUT and STDERR in a multi-process environment!
    #   instead we'll use a tem file
    my ( $th, $tn ) = tempfile( $self->server->temp_dir. "/file-XXXXXX", UNLINK => 1 );
    
    # wheter uses stdin or use file name
    my $stdin = 1;
    my ( $input_handle, $input_file ); # in handle, in file
    
    # pritn to file and give this file to command line
    my $file_mode = 0;
    if ( $cmd =~ /%file%/ ) {
        $file_mode++;
        ( $input_handle, $input_file ) = tempfile( $self->server->temp_dir. "/file-XXXXXX", UNLINK => 0 );
    }
    
    # open command line and print to it
    else {
        open $input_handle, '|-', "$cmd 1>\"$tn\" 2>\"$tn\"";
    }
    
    # open now the mail file and pipe
    open my $fh, '<', $self->file;
    
    # print whole mime data to pipe
    while ( my $l = <$fh> ) {
        print $input_handle $l;
    }
    
    # close input and command
    close $fh;
    close $input_handle;
    
    # in file mode: provide file name as input
    my $system_result = 0;
    if ( $file_mode ) {
        ( my $cmd_file = $cmd ) =~ s/%file%/$input_file/;
        $self->logger->debug3( "Run command '$cmd_file'" );
        `$cmd_file 1>"$tn" 2>"$tn"`;
        $system_result = $?;
    }
    
    # read now output from tempfile and remove it.. break after first empty line
    #   to assure we'll get only headers!!
    reset $th;
    my $in = "";
    while ( my $l = <$th> ) {
        last if $l =~ /^$/;
        $in .= $l;
    }
    close $th;
    unlink( $tn ) if -f $tn;
    unlink( $input_file ) if $input_file && -f $input_file;
    
    return ( 1, $in, $system_result );
}


=head2 get_user

Determines the user for the command line script .. eg "dspam --user %user%"

=cut

sub get_user {
    my ( $self ) = @_;
    
    # getting hit from cache ?
    my $cache_name = $self->name. "-User-". $self->to;
    # my $cached = $self->cache->get( $cache_name );
    # return $cached if $cached;
    
    my $user;
    
    # using command to retreive home
    if ( $self->has_cmd_user ) {
        $user = $self->get_user_by_cmd;
        $self->logger->debug3( "Got user '$user' from cmd" ) if $user;
    }
    
    # having module fallback method ?
    elsif ( $self->can( 'get_user_fallback' ) ) {
        $user = $self->get_user_fallback;
        $self->logger->debug3( "Got user '$user' from fallback" ) if $user;
    }
    
    # determine fallback user
    $user ||= $self->has_default_user
        ? $self->default_user
        : $self->to
    ;
    $self->logger->debug3( "Got final user '$user'" );
    
    # write to cache
    $self->cache->set( $cache_name => $user );
    
    
    
    return $user;
}

=head2 get_user_by_cmd

Using the cmd_user command to determine any user/home 

=cut

sub get_user_by_cmd {
    my ( $self ) = @_;
    my ( $th, $tn ) = tempfile( $self->server->temp_dir. "/file-XXXXXX", UNLINK => 1 );
    open my $cmd_fh, '|-', $self->cmd_user. "1>\"$tn\"";
    print $cmd_fh $self->to;
    close $cmd_fh;
    reset $th;
    my ( $user ) = <$th>;
    chomp $user;
    close $th;
    unlink( $tn ) if -f $tn;
}



=head2 build_cmd

Can be overwritte by descendant module

Build cmd

=cut

sub build_cmd {
    my ( $self, $type ) = @_;
    my $meth = "cmd_$type";
    return $self->$meth;
}


=head1 AUTHOR

Ulrich Kautz <uk@fortrabbit.de>

=head1 COPYRIGHT

Copyright (c) 2010 the L</AUTHOR> as listed above

=head1 LICENCSE

This library is free software and may be distributed under the same terms as perl itself.

=cut



1;
