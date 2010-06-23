package Mail::Decency::ContentFilter::DSPAM;

use Moose;
extends qw/
    Mail::Decency::ContentFilter::Core::Cmd
    Mail::Decency::ContentFilter::Core::Spam
/;

use version 0.77; our $VERSION = qv( "v0.1.0" );

use mro 'c3';
use Data::Dumper;

=head1 NAME

Mail::Decency::ContentFilter::DSPAM

=head1 DESCRIPTION

@@ PRE-ALPHA @@

Still some issues with dspam chrooting. Maybe requires wrapper.

@@ PRE-ALPHA @@

Filter messages through dspam and get result.

=cut

has cmd_check => (
    is      => 'rw',
    isa     => 'Str',
    default => '/usr/bin/dspam --client --user %user% --classify'
);

has cmd_learn_spam => (
    is      => 'rw',
    isa     => 'Str',
    default => '/usr/bin/dspam --client --user %user% --mode=teft --class=spam --deliver=spam --stdout'
);

has cmd_unlearn_spam => (
    is      => 'rw',
    isa     => 'Str',
    default => '/usr/bin/dspam --client --user %user% --mode=toe --class=innocent --deliver=innocent --stdout'
);

has cmd_learn_ham => (
    is      => 'rw',
    isa     => 'Str',
    default => '/usr/bin/dspam --client --user %user% --mode=teft --class=innocent --deliver=innocent --stdout'
);

has cmd_unlearn_ham => (
    is      => 'rw',
    isa     => 'Str',
    default => '/usr/bin/dspam --client --user %user% --mode=toe --class=spam --deliver=spam --stdout'
);

=head1 METHODS


=head2 handle_filter_result

=cut

sub handle_filter_result {
    my ( $self, $result, $exit_status ) = @_;
    
    
    # oops, no result -> probably no acces
    if ( ! $result ) {
        $self->logger->error( "No result from DSPAM. Probably insufficient access rights (see TrustedUser in DSPAM docu)" );
        return ;
    }
    
    # oops, no command line found
    if ( $result =~ /: not found$/ ) {
        $self->logger->error( "Could not find dspam: $result / exit: $exit_status" );
        return;
    }
    
    # parse result
    my %parsed = map {
        my ( $n, $v ) = split( /\s*[:=]\s*/, $_, 2 );
        $v =~ s/^"//;
        $v =~ s/"$//;
        ( $n => lc( $v ) );
    } split( /\s*;\s*/, $result );
    
    # get weighting
    my $weight = 0;
    my @info = ();
    if ( $parsed{ result } eq 'innocent' ) {
        $weight = $self->weight_innocent;
    }
    elsif ( $parsed{ result } eq 'spam' ) {
        $weight = $self->weight_spam;
    }
    $self->logger->debug0( "Score mail to '$weight'" );
    $self->logger->debug3( "Dspam result: $result" );
    
    # add info for noisy headers
    push @info, (
        "DSPAM result: $parsed{ result }",
        "DSPAM confidence: $parsed{ confidence }",
        "DSPAM probability: $parsed{ probability }",
        "DSPAM class: $parsed{ class }",
    );
    
    # add weight to content filte score
    return $self->add_spam_score( $weight, \@info );
}


=head1 SEE ALSO

=over

=item * L<Mail::Decency::ContentFilter::Core::Cmd>

=item * L<Mail::Decency::ContentFilter::Core::Spam>

=item * L<Mail::Decency::ContentFilter::Bogofilter>

=item * L<Mail::Decency::ContentFilter::CRM114>


=back

=head1 AUTHOR

Ulrich Kautz <uk@fortrabbit.de>

=head1 COPYRIGHT

Copyright (c) 2010 the L</AUTHOR> as listed above

=head1 LICENCSE

This library is free software and may be distributed under the same terms as perl itself.

=cut

1;
