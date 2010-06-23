package Mail::Decency::ContentFilter::Cookbook;

use strict;
use warnings;

use version 0.77; our $VERSION = qv( "v0.1.0" );

=head1 NAME

Mail::Decency::ContentFilter::Cookbook - How to write a content filter module

=head1 DESCRIPTION

This module contains a description on howto write a content filter module.

=head1 EXAMPLES

Hope this helps to understand what you can do. Have a look at the existing modules for more examples. Also look at L<Mail::Decency::ContentFilter::Core> for available methods.

=head2 SIMPLE EXAMPLE


    package Mail::Decency::ContentFilter::MyModule;
    
    use Moose;
    extends 'Mail::Decency::ContentFilter::Core';
    
    has some_key => ( is => 'rw', isa => 'Bool', default => 0 );
    
    #
    # The init method is kind of a new or BUILD method, which should
    #   init all configurations from the YAML file
    #
    sub init {
        my ( $self ) = @_;
        
        # in YAML:
        #   ---
        #   some_key: 1
        $self->some_key( 1 )
            if $self->config->{ some_key };
    }
    
    #
    # The handle method will be called by the ContentFilter server each time a new
    #   mail is filtered
    #
    
    sub handle {
        my ( $self ) = @_;
        
        # get the temporary queue file
        my $file = $self->file;
        
        # read the size
        my $size = $self->file_size;
        
        # manipulate the MIME::Entity object of the current
        $self->mime->head->add( 'X-MyModule' => 'passed' );
        $self->write_mime;
        
        # get sender and recipient
        my $sender = $self->from;
        my $recipient = $self->to;
        
        # access the datbaase
        my $data_ref = $self->database->get( schema => table => $search_ref );
        $data_ref->{ some_attrib } = time();
        $self->database->get( schema => table => $search_ref, $data_ref );
        
        # access the cache
        my $cached_ref = $self->cache->get( "cache-name" ) || { something => 1 };
        $cached_ref->{ something } ++;
        $self->cache->set( "cache-name" => $cached_ref );
        
    }

=head2 SPAM FILTER EXAMPLE

    package Mail::Decency::ContentFilter::MySpamFilter;
    
    use Moose;
    extends qw/
        Mail::Decency::ContentFilter::Core::Spam
    /;
    
    
    sub handle {
        my ( $self ) = @_;
        
        # throws exception if spam is recognized
        $self->add_spam_score( -100, "You shall not send me mail" )
            if $self->from eq 'evil@sender.tld';
        
    }

=head2 VIRUS FILTER EXAMPLE

    package Mail::Decency::ContentFilter::MySpamFilter;
    
    use Moose;
    extends qw/
        Mail::Decency::ContentFilter::Core::Virus
    /;
    
    sub handle {
        my ( $self ) = @_;
        
        # throws exception
        if ( time() % 86400 == 0 ) {
            $self->found_virus( "Your daily virus" );
        }
    }

=head1 INCLUDE MODULE

To include the module, simple add it in your contnet filter

=head2 YAML

In content-filter.yml ...

    ---
    
    # ..
    
    filters:
        - MyModule:
            some_key: 1
        - MyModule: /path/to/my-module.yml
    

=head2 PERL

    my $content_filter = Mail::Decency::ContentFilter->new(
        # ..
        filters => [
            { MyModule => { some_key => 1 } }
        ]
    );

=head1 AUTHOR

Ulrich Kautz <uk@fortrabbit.de>

=head1 COPYRIGHT

Copyright (c) 2010 the L</AUTHOR> as listed above

=head1 LICENCSE

This library is free software and may be distributed under the same terms as perl itself.

=cut


1;
