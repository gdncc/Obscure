unit module WycheproofHelper;

use Test;

# Root of the wycheproof submodule checkout.
my $base = $?FILE.IO.parent.parent.add('data/wycheproof');

sub ensure-wycheproof-vectors() is export {
    my $marker = $base.add('testvectors_v1');
    return True if $marker.d;

    # Submodule exists but not initialised — try to fetch
    my $repo-root = $base.parent.parent;  # t/data/wycheproof -> repo root
    my $proc = run 'git', '-C', $repo-root.Str,
                   'submodule', 'update', '--init', '--', 't/data/wycheproof',
                   :out, :err;
    if $proc.exitcode == 0 && $marker.d {
        diag 'Wycheproof submodule initialised';
        return True;
    }

    diag 'Wycheproof vectors unavailable (git submodule not initialised)';
    return False;
}

sub wycheproof-path(Str $file --> IO::Path) is export {
    $base.add("testvectors_v1/$file");
}
