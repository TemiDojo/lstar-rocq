open Mealy
open Specif
open Teacher
open Stdlib
open Config

(** Input alphabet *)
module S = struct
  type t =
    | CLIENT_HELLO
    | CLIENT_KEY_EXCHANGE
    | CHANGE_CIPHER_SPEC
    | FINISHED
    | APPLICATION_DATA
    | HEARTBEAT
    | EMPTY_APPLICATION_DATA

  let string_of_t = function
    | CLIENT_HELLO ->
        "CLIENT_HELLO"
    | CLIENT_KEY_EXCHANGE ->
        "CLIENT_KEY_EXCHANGE"
    | CHANGE_CIPHER_SPEC ->
        "CHANGE_CIPHER_SPEC"
    | FINISHED ->
        "FINISHED"
    | APPLICATION_DATA ->
        "APPLICATION_DATA"
    | EMPTY_APPLICATION_DATA ->
        "EMPTY_APPLICATION_DATA"
    | HEARTBEAT ->
        "HEARTBEAT"

  let t_of_string : string -> (t, string) Datatypes.result = function
    | "HEARTBEAT" ->
        Ok HEARTBEAT
    | "CLIENT_HELLO" ->
        Ok CLIENT_HELLO
    | "CLIENT_KEY_EXCHANGE" ->
        Ok CLIENT_KEY_EXCHANGE
    | "CHANGE_CIPHER_SPEC" ->
        Ok CHANGE_CIPHER_SPEC
    | "FINISHED" ->
        Ok FINISHED
    | "APPLICATION_DATA" ->
        Ok APPLICATION_DATA
    | "EMPTY_APPLICATION_DATA" ->
        Ok EMPTY_APPLICATION_DATA
    | _ ->
        Error "t_of_string"

  let eq_dec x y = x = y

  let enum =
    [ CLIENT_HELLO
    ; CLIENT_KEY_EXCHANGE
    ; CHANGE_CIPHER_SPEC
    ; FINISHED
    ; APPLICATION_DATA
    ; HEARTBEAT
    ; EMPTY_APPLICATION_DATA ]

  type str = t list

  let string_of_str s = String.concat "" (List.map string_of_t s)
end

(** output alphabet *)
module O = struct
  type t = string

  let string_of_t s = s

  let t_of_string s : (t, string) Datatypes.result = Ok s

  let eq_dec x y = x = y

  let enum =
    [ "SERVER_HELLO"
    ; "CERTIFICATE"
    ; "SERVER_KEY_EXCHANGE"
    ; "CERTIFICATE_REQUEST"
    ; "SERVER_HELLO_DONE"
    ; "CHANGE_CIPHER_SPEC"
    ; "FINISHED" ]

  type str = t list
end

module Teacher : MEALYTEACHER with module S = S and module O = O = struct
  module S = S
  module O = O
  module M = Mealy (S) (O)

  let output_lang_live (s : S.str) (a : S.t) : O.t =
    Config.init_and_seed_rng () ;
    let config = TLSConfig.{host= "127.0.0.1"; port= 4433; timeout_ms= 100.0} in
    let sul = TLSSUL.create config in
    TLSSUL.pre sul ;
    let result =
      try
        List.iter
          (fun symbol -> ignore (TLSSUL.step sul (S.string_of_t symbol)))
          s ;
        TLSSUL.step sul (S.string_of_t a)
      with e -> TLSSUL.post sul ; raise e
    in
    TLSSUL.post sul ; result

  let cache : (S.str * S.t, O.t) Hashtbl.t = Hashtbl.create 4096

  let output_lang (s : S.str) (a : S.t) : O.t =
    match Hashtbl.find_opt cache (s, a) with
    | Some cached ->
        cached
    | None ->
        let result = output_lang_live s a in
        Hashtbl.add cache (s, a) result ;
        result

  let equiv_query (m : 'a M.t) : S.str option =
    let rec find_counter_example depth current_strings =
      if depth >= int_of_float (2. ** 12.) then
        None
      else
        match current_strings with
        | [] ->
            None
        | s :: rest -> (
          match (s, List.rev s) with
          | [], _ | _, [] ->
              find_counter_example (depth + 1) rest
          | hd :: tl, a :: rprefix ->
              let prefix = List.rev rprefix in
              let mealy_out = M.last_output m hd tl in
              let spec_out = output_lang prefix a in
              (* Printf.printf "Depth=%d\n %!" depth; *)
              if mealy_out <> spec_out then (
                Some s
              ) else
                let next_gen = List.map (fun c -> s @ [c]) S.enum in
                find_counter_example (depth + 1) (rest @ next_gen) )
    in
    find_counter_example 0 (List.map (fun c -> [c]) S.enum)

  let fuel : int = Int.max_int
end

module LstarLearner = MealyLstarLearner (Teacher)
module KVLearner = MealyKVLearner (Teacher)
module TTTLearner = MealyTTTLearner (Teacher)
module MP = MealyPrinter (Teacher)

let rec enumberate (n : int) : S.str list =
  if n <= 0 then
    [[]]
  else
    let prev = enumberate (n - 1) in
    let prepend c l = List.map (fun s -> [c] @ s) l in
    [[]] @ List.concat_map (fun c -> prepend c prev) S.enum

let dedup l =
  List.fold_left
    (fun acc x ->
      if List.mem x acc then
        acc
      else
        x :: acc )
    [] l
  |> List.rev

let print_results name m n =
  Printf.printf "\n=== %s ===\n%!" name ;
  print_endline "Mealy machine found" ;
  MP.print_mealy m ;
  Printf.printf "DOT file at %s\n" (MP.to_dot ~name:(name ^ "_vending") m) ;
  ()

let () = 
        Sys.set_signal Sys.sigpipe Sys.Signal_ignore;
        print_results "Mealy-L*" (LstarLearner.mlstar ()) 3
 (*print_results "Mealy-KV" (KVLearner.mkv ()) 3*)
 (*print_results "Mealy- TTT" (TTTLearner.mttt ()) 3 *)
