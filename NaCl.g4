grammar NaCl;

/* Lexer */

Whitespace: (' ' | '\t' | '\n' | '\r') -> channel(1);

// Characters
Hyphen : 	'-';
Slash: 		'/' ;
Dot: 		'.' ;
Colon: 		':';
Comma: 		',';
Hash: 		'#';
Curly_bracket_start: 	'{';
Curly_bracket_end: 		'}';
Square_bracket_start: 	'[';
Square_bracket_end: 	']';
Parenthesis_start: 		'(';
Parenthesis_end: 		')';
Quotes: 				'"';

// Comparison operators
Equals: 			'==';
Not_equals: 		'!=';
Greater_than: 		'>';
Less_than: 			'<';
Greater_or_equals: 	'>=';
Less_or_equals: 	'<=';

In: 'in' | 'IN';

// Logical operators
And: 	'&&' 	| 	'and';
Or: 	'||' 	| 	'or';
Not: 	'!'		| 	'not';

// Keywords
If: 	'if';
Else: 	'else';

// Comments
Line_comment_start: 	'//';
Block_comment_start: 	'/*';
Block_comment_end: 		'*/';

Hash_comment: 	Hash ~[\r\n]* -> skip;
Line_comment: 	Line_comment_start ~[\r\n]* -> skip;
Block_comment: 	Block_comment_start .*? Block_comment_end -> skip;

fragment A: [aA];
fragment B: [bB];
fragment C: [cC];
fragment D: [dD];
fragment E: [eE];
fragment F: [fF];

fragment D0: '0';
fragment D1: '1';
fragment D2: '2';
fragment D3: '3';
fragment D4: '4';
fragment D5: '5';
fragment D6: '6';
fragment D7: '7';
fragment D8: '8';
fragment D9: '9';

fragment Non_zero_digit: (D1 | D2 | D3 | D4 | D5 | D6 | D7 | D8 | D9);

fragment Digit: (D0 | Non_zero_digit);

fragment Hexdigit: Digit | ( A | B | C | D | E | F );

// This gives no room for fe80:0:0:0:0:0:0:ea1, only fe80:0000:0000:0000:0000:0000:0000:0ea1
// time cpp_diff.sh:
//  real    0m7.130s
//  user    0m5.944s
//  sys     0m1.108s
fragment H16: Hexdigit Hexdigit Hexdigit Hexdigit;
IPv6: H16 Colon H16 Colon H16 Colon H16 Colon H16 Colon H16 Colon H16 Colon H16;

// vs.

/*
// This GIVES room for fe80:0:0:0:0:0:0:ea1
// time cpp_diff.sh:
//  real    0m7.671s
//  user    0m6.489s
//  sys     0m1.101s
fragment H16: Hexdigit Hexdigit Hexdigit Hexdigit
    | Hexdigit Hexdigit Hexdigit
    | Hexdigit Hexdigit
    | Hexdigit
    ;
IPv6: H16 Colon H16 Colon H16 Colon H16 Colon H16 Colon H16 Colon H16 Colon H16;
*/

// vs.

/*
// Gives room for short form, f.ex. ::1 (incl. LS32 / IPv4 syntax)
// However, transpilation takes forever:
// time cpp_diff.sh:
//  real    0m25.698s
//  user    0m24.206s
//  sys     0m1.368s
IPv4: Number Dot Number Dot Number Dot Number;
fragment H16: Hexdigit Hexdigit Hexdigit Hexdigit
    | Hexdigit Hexdigit Hexdigit
    | Hexdigit Hexdigit
    | Hexdigit
    ;
IPv6: H16 Colon H16 Colon H16 Colon H16 Colon H16 Colon H16 Colon LS32
    | Colon Colon H16 Colon H16 Colon H16 Colon H16 Colon H16 Colon LS32
    | H16? Colon Colon H16 Colon H16 Colon H16 Colon H16 Colon LS32
    | ((H16 Colon)? H16)? Colon Colon H16 Colon H16 Colon H16 Colon LS32
    | (((H16 Colon)? H16 Colon)? H16)? Colon Colon H16 Colon H16 Colon LS32
    | ((((H16 Colon)? H16 Colon)? H16 Colon)? H16)? Colon Colon H16 Colon LS32
    | (((((H16 Colon)? H16 Colon)? H16 Colon)? H16 Colon)? H16)? Colon Colon LS32
    | ((((((H16 Colon)? H16 Colon)? H16 Colon)? H16 Colon)? H16 Colon)? H16)? Colon Colon H16
    ;
LS32: H16 Colon H16
    | IPv4
    ;
*/

Number: D0 | ( Non_zero_digit Digit* )+;

// NOTE: Identifier has to be at the end - after all the other lexer rules
Identifier: [a-zA-Z] [a-zA-Z0-9_-]*;	// valid names of variables and characters in comments

/* Parser */

// ---------- value ----------

value: primitive_type | rng | string | value_name | obj | list_t;

primitive_type: numeric_type | bool_val | ipv4_cidr;
numeric_type: integer | decimal | ipv4_addr | ipv6_addr;
bool_val: 'true' | 'false';
ipv4_cidr: ipv4_addr cidr_mask;
cidr_mask: (Slash integer);

integer: Number
        | Parenthesis_start Hyphen Number Parenthesis_end;
decimal: Number Dot Number
        | Parenthesis_start Hyphen Number Dot Number Parenthesis_end;
ipv4_addr: Number Dot Number Dot Number Dot Number;
ipv6_addr: IPv6;

rng: numeric_type Hyphen numeric_type;
string: Quotes (~(Quotes) | '\\n')* Quotes; // Allowed to write \n inside a string
value_name: Identifier | Identifier Dot value_name;

obj: Curly_bracket_start key_value_list Curly_bracket_end;
key_value_list: (key_value_pair Comma)* key_value_pair;
key_value_pair: key Colon value;
key: Identifier;

list_t: Square_bracket_start value_list Square_bracket_end;
value_list: (value Comma)* value;

// ---------- function ----------

function: type_t Colon Colon subtype name? Curly_bracket_start body Curly_bracket_end;
type_t: Identifier;
subtype: Identifier;
name: Identifier;
body: body_element+;
body_element: function | action | conditional;

action: name | name Parenthesis_start value_list? Parenthesis_end;

conditional: If Parenthesis_start bool_expr Parenthesis_end Curly_bracket_start body Curly_bracket_end (Else Curly_bracket_start body Curly_bracket_end)?;

bool_expr:	Not? value
		| 	Not? comparison
		| 	Not? Parenthesis_start comparison Parenthesis_end
		| 	Not? Parenthesis_start bool_expr Parenthesis_end
		|	bool_expr logical_operator bool_expr
		| 	Not? Parenthesis_start bool_expr logical_operator bool_expr Parenthesis_end;
comparison: lhs comparison_operator rhs;
lhs: value;
rhs: value;
logical_operator: 		And | Or;
comparison_operator: 	Equals | Not_equals
						| Greater_than | Less_than
						| Greater_or_equals | Less_or_equals
						| In;

// ---------- typed_initializer ----------

typed_initializer: type_t name value;

// ---------- initializer ----------

initializer: value_name Colon value;

// ---------- prog ----------

expr: function
	| typed_initializer
	| initializer;

prog: (expr)* EOF;