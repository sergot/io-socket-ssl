module libclient;

use LibraryMake;

our sub library {
    my $so = get-vars('')<SO>;
    for @*INC {
        if ($_~'/libclient'~$so).IO ~~ :f {
            return $_~'/libclient'~$so;
        }
    }
    die "Unable to find library";
}
