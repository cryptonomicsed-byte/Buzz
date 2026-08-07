;; ci-green.wat — "the named commit is green on CI"
;;
;; An *observational* falsifier: it reads one fact from the world through the
;; sandbox's observation interface, and nothing else. Its manifest grants
;; exactly `ci:status`, so a reviewer deciding whether to run it can read the
;; entire blast radius in one line.
;;
;; It refutes the claim unless CI reports the literal string "green". Note what
;; it does *not* do: if the observation was never gathered it emits
;; `indeterminate` rather than guessing. A probe that cannot see is not a probe
;; that disagrees.
;;
;;   manifest: {"observations":["ci:status"]}
;;   verdicts: 1 = holds, 2 = fails, 3 = indeterminate

(module
  (import "crucible" "observe_len"  (func $observe_len  (param i32 i32) (result i32)))
  (import "crucible" "observe_read" (func $observe_read (param i32 i32 i32)))
  (import "crucible" "emit"         (func $emit         (param i32 i32 i32)))

  (memory (export "memory") 1)

  ;; 0..9    the observation key
  ;; 16..    messages
  ;; 256..   where the observed value lands
  (data (i32.const 0)   "ci:status")
  (data (i32.const 16)  "ci reported green")
  (data (i32.const 48)  "ci did not report green")
  (data (i32.const 96)  "ci status was never gathered")

  (func (export "crucible_falsify")
    (local $len i32)

    (local.set $len (call $observe_len (i32.const 0) (i32.const 9)))

    ;; -1 means the runner never gathered it. Say so; do not assume.
    (if (i32.lt_s (local.get $len) (i32.const 0))
      (then
        (call $emit (i32.const 3) (i32.const 96) (i32.const 28))
        (return)))

    (if (i32.ne (local.get $len) (i32.const 5))
      (then
        (call $emit (i32.const 2) (i32.const 48) (i32.const 23))
        (return)))

    (call $observe_read (i32.const 0) (i32.const 9) (i32.const 256))

    ;; Compare against "green" one byte at a time. No allocator, no string
    ;; library, no imports beyond the three above — that is the whole point.
    (if (i32.and
          (i32.and
            (i32.eq (i32.load8_u (i32.const 256)) (i32.const 103))   ;; g
            (i32.eq (i32.load8_u (i32.const 257)) (i32.const 114)))  ;; r
          (i32.and
            (i32.and
              (i32.eq (i32.load8_u (i32.const 258)) (i32.const 101)) ;; e
              (i32.eq (i32.load8_u (i32.const 259)) (i32.const 101)));; e
            (i32.eq (i32.load8_u (i32.const 260)) (i32.const 110)))) ;; n
      (then (call $emit (i32.const 1) (i32.const 16) (i32.const 17)))
      (else (call $emit (i32.const 2) (i32.const 48) (i32.const 23)))))
)
