use v6.d;

unit module Obscure::Completion;

# used for Random API

role Completion is export {};
role Successful does Completion is export {};
# Partial success e.g. the full buffer was not populated
role Partial[Int \read] does Completion is export {
    has Int $.read = read;
    # how many bytes we read;
};
role Unsuccessful[Int \result] does Completion is export {
    has Int $.result = result;
};
# UnsuccessfulNoErrorCodefor when no error code is available
role UnsuccessfulNoErrorCode does Completion is export {};

# Trait for API calls where failure is not zero, and return int32
multi sub trait_mod:<is> (Routine $s, :$error-type where * ~~ "notzeroi32") is export {
    $s.wrap(sub ($arg) {
        my int32 $result = callwith($arg);
        return $result == 0 ?? Successful !! Unsuccessful[$result];
        CATCH { when X::TypeCheck::Binding::Parameter {
            return UnsuccessfulNoErrorCode
        } }
    });
}

# Trait for API calls where failure is -1, and returns ssize_t
multi sub trait_mod:<is> (Routine $s, :$error-type where * ~~ "minusonessize_t") is export {
    $s.wrap(sub ($arg) {
        $arg ~~ Buf[uint8] or die "argument must be of type Buf[uint8]";
        my Int $result = callwith($arg);
        given $result {
            when -1 { Unsuccessful[$result] }
            when * == $arg.elems { Successful }
            default { Partial[$result] }
        }
    });
}
