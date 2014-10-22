package Mail::Decency::Core::SessionItem;

use Moose;

use version 0.77; our $VERSION = qv( "v0.1.0" );

=head1 NAME

Mail::Decency::Core::SessionItem

=head1 DESCRIPTION

Represents an session item for either policy or content filter.
Base class, don't instantiate!

=head1 CLASS ATTRIBUTES

=head2 id

The primary identifier

=cut

has id => ( is => 'rw', isa => "Str", required => 1 );

=head2 spam_score

Current spam score

=cut

has spam_score => ( is => 'rw', isa => 'Num', default => 0 );

=head2 spam_details

List of details for spam

=cut

has spam_details => ( is => 'rw', isa => 'ArrayRef[Str]', default => sub { [] } );

=head2 flags

Hashref of flags which can be set

=cut

has flags => ( is => 'rw', isa => 'HashRef[Int]', default => sub { {} } );

=head2 cache

Accessor to the parentl cache

=cut

has cache => ( is => 'rw', isa => 'Mail::Decency::Helper::Cache', required => 1, weak_ref => 1 );



=head1 METHODS

=head2 add_spam_score

add score 

=cut

sub add_spam_score {
    my ( $self, $add ) = @_;
    return $self->spam_score( $self->spam_score + $add );
}


=head2 add_spam_details

Adds spam details to the list

=cut

sub add_spam_details {
    my ( $self, @details ) = @_;
    push @{ $self->spam_details }, grep { defined $_ && $_ ne "" } @details;
    return;
}


=head2 (del|set|has)_flag

Set, remove or query wheter has flag

=cut

sub has_flag {
    my ( $self, $flag ) = @_;
    return defined $self->flags->{ $flag };
}

sub set_flag {
    my ( $self, $flag ) = @_;
    return $self->flags->{ $flag } = 1;
}

sub del_flag {
    my ( $self, $flag ) = @_;
    return delete $self->flags->{ $flag };
}


=head2 unset

=cut

sub unset {
    my ( $self ) = @_;
    delete $self->{ $_ } for keys %$self
}


=head1 AUTHOR

Ulrich Kautz <uk@fortrabbit.de>

=head1 COPYRIGHT

Copyright (c) 2010 the L</AUTHOR> as listed above

=head1 LICENCSE

This library is free software and may be distributed under the same terms as perl itself.

=cut

1;
