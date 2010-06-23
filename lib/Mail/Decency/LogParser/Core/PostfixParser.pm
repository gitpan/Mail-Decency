package Mail::Decency::LogParser::Core::PostfixParser;

use Moose::Role;

use version 0.77; our $VERSION = qv( "v0.1.0" );

use Data::Dumper;

=head1 NAME

Mail::Decency::LogParser::Core::LogParser

=head1 DESCRIPTION

Parse logs in postfix style

=cut

our $RX_HOST_AND_IP = qr/([^\]]*?)\[([^\]]+?)\]/;

=head1 METHODS

=cut

=head2 parse_line

=cut

sub parse_line {
    my ( $self, $line ) = @_;
    
    #$self->logger->debug3( "Got line '$line'" );
    return if index( $line, 'postfix/' ) == -1 || index( $line, ' warning:' ) > -1;
    
    return if $line =~ / (dis)?connect from/;
    
    my $ref = {};
    my $queue_id;
    
    # found REJECT
    if ( index( $line, ' NOQUEUE:' ) > -1 ) {
        if ( $line =~ / reject: RCPT from $RX_HOST_AND_IP: (\d\d\d) [^:]+?: ([^;]*?);/ ) {
            $ref->{ reject }++;
            $ref->{ final }++;
            $ref->{ host }    = $1;
            $ref->{ ip }      = $2;
            $ref->{ code }    = $3;
            $ref->{ message } = $4;
        }
        else {
            return;
        }
    }
    
    # found QUEUED message
    else {
        
        # parse ..
        my ( $prog, $id, $msg ) = $line =~ /
            postfix \/ ([^\[]+)   # cleanup, bounce, ..
            \[\d+\]:\s+           # some process id
            ([A-Z0-9]+):\s+       # the queue id
            (.+)                  # rest of the message
        /x;
        
        # mark as queued
        $ref->{ queued } ++;
        
        # remember id and prog
        $queue_id = $ref->{ id } = $id;
        $ref->{ prog } = $prog;
    }
    
    # got sender or recupuent
    my $found_from = 0;
    while ( $line =~ /\b(from|to)=<([^>]*)/g ) {
        my ( $type, $value ) = ( $1, $2 );
        $ref->{ "${type}_address" } = $value;
        if ( $value =~ /^[^@]+@(.+?)$/ ) {
            $ref->{ "${type}_domain" } = $1;
        }
        $found_from ++ if $type eq 'from';
    }
    
    # got helo
    if ( $line =~ /helo=<([^>]*)/ ) {
        $ref->{ helo } = $1;
    }
    
    # got sender
    if ( $line =~ /client=$RX_HOST_AND_IP/ ) {
        $ref->{ rdns } = $1;
        $ref->{ ip }   = $2;
    }
    
    # workign on queue id (not no-queue)
    if ( $queue_id ) {
        
        # got relay target
        if ( $line =~ /\brelay=([^\[,]*)(?:\[([^\]]*)\])?/ ) {
            $ref->{ relay_host } = $1;
            $ref->{ relay_ip }   = $2 || '';
        }
        
        # got suze
        if ( $line =~ /\bsize=(\d+)/ ) {
            $ref->{ size } = $1;
        }
        
        # got final status
        if ( $line =~ /\bstatus=(bounced|sent|deferred)\b/ ) {
            $ref->{ $1 }++;
            $ref->{ final }++;
        }
        
        # got final remove
        elsif ( $line =~ / removed$/ ) {
            $ref->{ removed }++;
        }
        
        # try read current from cache
        my $cached = $self->cache->get( "QUEUE-$queue_id" );
        if ( $cached ) {
            
            # not final if has next
            if ( $cached->{ next_id } ) {
                delete $ref->{ final };
            }
            
            # update self
            $ref = { %$cached, %$ref };
            delete $ref->{ final } if $found_from;
            delete $ref->{ deferred } if $ref->{ sent };
        }
        
        
        # non delivery
        if ( $line =~ /sender non-delivery notification: ([A-Z0-9]+)/ ) {
            my $next_id = $1;
            
            # create new cache entry
            my %next = %$ref;
            push @{ $next{ prev } ||= [] }, $ref;
            $next{ orig_from } = $ref->{ from } if $ref->{ from };
            $next{ prev_id }   = $queue_id;
            $next{ queue_id }  = $next_id;
            $next{ is_bounce } = 1;
            delete $next{ next_id };
            
            # save next instance to cache
            $self->cache->set( "QUEUE-$next_id", \%next, time() + 600 );
            
            # current is not final anymore
            $ref->{ next_id } = $next_id;
            delete $ref->{ final };
        }
        
        # update current to cache
        $self->cache->set( "QUEUE-$queue_id", $ref, time() + 600 );
    }
    
    $queue_id ||= "NOQUEUE";
    $self->logger->debug3( Dumper( {
        $queue_id => $ref,
        LINE      => $line
    } ) ) if 0;
    
    return $ref;
}

=head1 AUTHOR

Ulrich Kautz <uk@fortrabbit.de>

=head1 COPYRIGHT

Copyright (c) 2010 the L</AUTHOR> as listed above

=head1 LICENCSE

This library is free software and may be distributed under the same terms as perl itself.

=cut

1;
