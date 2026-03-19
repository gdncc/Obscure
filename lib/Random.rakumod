use v6.d;

unit module Obscure::Random;

my $module;

given $*KERNEL.name {
    when 'darwin' {
        given  $*DISTRO.name {
            when 'macos' { $module = "Obscure::RandomInternal::macOS"; }
            default { die "no support for this darwin distribution"; }
        }
    }
    when 'linux' { $module = "Obscure::RandomInternal::linux"; }
    when 'win32' { die "not implemented"; }
    default {
        die "no support for this kernel"; }
}

(try require ::($module) <&secure-random-internal>) === Nil and die "failed to load module!";

# secure-random() may return one of the following:
# Obscure::Completion::Successful;
# Obscure::Completion::Partial[number of bytes actually read instead of requested];
# Obscure::Completion::Unsuccessful[OS error code];

our &secure-random  is export;
&secure-random = &secure-random-internal;
