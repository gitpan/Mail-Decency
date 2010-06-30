package Mail::Decency::ContentFilter::SpamAssassin;

use Moose;
extends qw/
    Mail::Decency::ContentFilter::Core::Cmd
    Mail::Decency::ContentFilter::Core::Spam
    Mail::Decency::ContentFilter::Core::WeightTranslate
/;

use version 0.74; our $VERSION = qv( "v0.1.4" );

use mro 'c3';
use Data::Dumper;
use File::Temp qw/ tempfile /;

=head1 NAME

Mail::Decency::ContentFilter::SpamAssassin

=head1 DESCRIPTION

@@ PRE-ALPHA @@

Untested

@@ PRE-ALPHA @@

Filter messages through spamc and translate results

=head2 CONFIG

    ---
    
    disable: 0
    #max_size: 0
    #timeout: 30
    
    cmd_check: '/usr/bin/spamc -u %user% --headers'
    

=head1 CLASS ATTRIBUTES

=cut

has cmd_check => (
    is      => 'rw',
    isa     => 'Str',
    default => '/usr/bin/spamc -u %user% --headers'
);


=head1 METHODS


=head2 handle_filter_result

=cut

sub handle_filter_result {
    my ( $self, $result ) = @_;
    
    my %header;
    
    # parse result
    my %parsed = map {
        my ( $n, $v ) = /^X-Spam-(\S+?):\s+(.*?)$/;
        ( $n => lc( $v ) );
    } grep {
        /^X-Spam-/;
    } split( /\n/, $result );
    
    # found status ?
    if ( $parsed{ Status } ) {
        my $weight = 0;
        
        # wheter the whole is spam!
        my $status = index( $parsed{ Status }, 'No' ) == 0
            ? 'ham'
            : 'spam'
        ;
        
        my @info = ( "SpamAssassin status: $status" );
        
        # get sa test info
        my $sa_tests = $parsed{ Status } =~ /tests=([A-Z0-9,]+)/;
        $sa_tests ||= "";
        push @info, "SpamAssassin tests: $sa_tests";
        
        # translate weight from crm114 to our requirements
        if ( $self->has_weight_translate ) {
            
            # fetch weight and translate
            my ( $sa_weight ) = $parsed{ Status } =~ /score=(\-?\d+(?:\.\d+)?)/;
            $weight = $self->translate_weight( $sa_weight );
            
            # remember info for headers
            push @info, "SpamAssassin score: $sa_weight";
            
            $self->logger->debug0( "Translated score from '$sa_weight' to '$weight'" );
        }
        
        # just use it's results -> spam
        elsif ( $status eq 'spam' ) {
            $weight = $self->weight_spam;
            $self->logger->debug0( "Use spam status, set score to '$weight'" );
        }
        
        # s ham
        elsif ( $status eq 'ham' ) {
            $weight = $self->weight_innocent;
            $self->logger->debug0( "Use ham status, set score to '$weight'" );
        }
        
        # add weight to content filte score
        return $self->add_spam_score( $weight, \@info );
    }
    
    # return ok
    return ;
}


=head1 AUTHOR

Ulrich Kautz <uk@fortrabbit.de>

=head1 COPYRIGHT

Copyright (c) 2010 the L</AUTHOR> as listed above

=head1 LICENCSE

This library is free software and may be distributed under the same terms as perl itself.

=cut


1;
