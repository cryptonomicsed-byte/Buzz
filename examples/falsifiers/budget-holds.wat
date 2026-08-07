;; budget-holds.wat — "the declared cost is within the declared budget"
;;
;; A *pure* falsifier: its manifest grants no observations at all, so it is a
;; closed computation over the claim's declared inputs. Two agents anywhere in
;; the world must get byte-identical output from it, and if they do not, the
;; kernel is entitled to call the claim `Nondeterministic` rather than trying to
;; average the disagreement away.
;;
;; It expects the claim's `inputs` JSON to contain the two numbers as raw
;; little-endian u32s appended after the JSON — kept crude deliberately, so the
;; module stays readable: a real one would parse. Here the host writes the
;; declared input bytes at offset 0 and we read the first two u32 words.
;;
;;   manifest: {"observations":[]}

(module
  (import "crucible" "input_len"  (func $input_len  (result i32)))
  (import "crucible" "input_read" (func $input_read (param i32)))
  (import "crucible" "emit"       (func $emit       (param i32 i32 i32)))

  (memory (export "memory") 1)

  (data (i32.const 512) "cost is within budget")
  (data (i32.const 560) "cost exceeds budget")
  (data (i32.const 608) "inputs too short to check")

  (func (export "crucible_falsify")
    (if (i32.lt_s (call $input_len) (i32.const 8))
      (then
        (call $emit (i32.const 3) (i32.const 608) (i32.const 25))
        (return)))

    (call $input_read (i32.const 0))

    (if (i32.le_u (i32.load (i32.const 0)) (i32.load (i32.const 4)))
      (then (call $emit (i32.const 1) (i32.const 512) (i32.const 21)))
      (else (call $emit (i32.const 2) (i32.const 560) (i32.const 19)))))
)
