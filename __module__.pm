#
# (c) 2015 FILIADATA GmbH
# 
# vim: set ts=2 sw=2 tw=0:
# vim: set expandtab:

package Certencryption;

use strict;
use warnings;

use Rex -base;
use Carp;
use MIME::Base64;
use Crypt::OpenSSL::RSA;

require Exporter;
use base qw(Exporter);
use vars qw(@EXPORT);

@EXPORT = qw(padding key_file decrypt encrypt generate_key);

my $key_file = "keys/default";
my $padding  = "pkcs1_oaep";

my %_valid_paddings = (
  no         => 0,
  pkcs1_oaep => 1,
  pkcs1      => 1,
  sslv23     => 1,
);


################################################################################
# TASKS
################################################################################

task generate_key => sub {
  my $params = shift;

  $params->{size} ||= 4096;
  $params->{name} ||= "default";

  my $rsa = Crypt::OpenSSL::RSA->generate_key($params->{size});
  my $private_key = $rsa->get_private_key_string;
  my $public_key  = $rsa->get_public_key_string;

  mkdir "keys" if(! -d "keys");

  open(my $fh, ">", "keys/$params->{name}") or die("Error writing to private key file: keys/$params->{name}: $!");
  print $fh $private_key;
  close($fh);

  open(my $pub_fh, ">", "keys/$params->{name}.pub") or die("Error writing to private key file: keys/$params->{name}.pub: $!");
  print $pub_fh $public_key;
  close($pub_fh);
};


################################################################################
# FUNCTIONS
################################################################################

sub padding {
  my ($p) = @_;
  if(exists $_valid_paddings{$p} && $_valid_paddings{$p}) {
    $padding = $p;
  }
  else {
    confess "Invalid padding mode.";
  }
}

sub key_file {
  $key_file = shift;
}

sub _use_padding {
  my ($o, $p) = @_;
  my $f = "use_${p}_padding";
  $o->$f();
}

sub encrypt {
  my ($str) = @_;

  confess 'No key file found.' if(! -f $key_file);

  my $key_string = _get_priv_key("$key_file.pub");

  my $o = Crypt::OpenSSL::RSA->new_public_key($key_string);
  _use_padding($o, $padding);

  my @chunks = grep { $_ } ($str =~ m/(.{0,300})/g);
  my $line = "";
  for my $chunk (@chunks) {
    $line .= encode_base64($o->encrypt($chunk), "") . "\n";
  }

  return encode_base64($line, "");
}

sub decrypt {
  my ($str) = @_;

  confess 'No key file found.' if(! -f $key_file);

  my $key_string = _get_priv_key($key_file);

  my $o = Crypt::OpenSSL::RSA->new_private_key($key_string);
  _use_padding($o, $padding);

  my @strr = split("\n", decode_base64($str));
  my $dec = "";
  for my $str (@strr) {
    eval {
      $dec .= $o->decrypt(decode_base64($str));
    } or do {
      confess "Error decrypting: $@";
    };
  }

  return $dec;
}

sub _get_priv_key {
  my ($file) = @_;

  my @lines = eval { local(@ARGV) = ($file); <>; };
  s/(\r|\n)//gms for @lines;

  join "\n", @lines;
}

1;

__END__

=pod

=head1 NAME

Certencryption - Store strings encrypted.

This is a module which stores strings (like passwords, private keys, ...) in a secure way. Certencryption uses OpenSSL private key for encryption.

=head1 SYNOPSIS

 use Certencryption;
   
 user "root";
 password decrypt($encrypted_string);
   

=head1 USAGE

To use this module you need a private key with which you can decrypt your data. You also need a public key with which you can encrypt your data.

=head2 KEY GENERATION

To generate a public/private keypair you can use the provided I<generate_key> task.

  rex Certencryption:generate_key [--name=default [--size=4096]]

This will create a folder I<keys> and place the two keyfiles in it.


=head2 REXFILE

To encrypt or decrypt strings you have to include the I<Certencryption> module in your Rexfile.

 use Certencryption;
   
 key_file "keys/default";
   
 user "root";
 password decrypt($encrypted_string);

The I<key_file> command tells the module which key file it should use for the decryption. To encrypt a string you also need to have a public key. In this example the public key should be found in I<keys/default.pub>.

 my $base64_encrypted_string = encrypt("this is secret");


=head2 PADDING

To define which padding should be used, you can define this with the I<padding> function. The default is I<pkcs1_oaep>. Valid padding option are:

=over 4

=item pkcs1_oaep (default)

=item pkcs1

=item sslv23 (due to a bug, only for decryption)

=back

=head1 COPYRIGHT

Copyright 2015 FILIADATA GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

