<?php
    function encode($input){ 
        $inputlen = strlen($input);
		$randkey = 5;
		$i = 0;
		while ($i < $inputlen) {
			$inputchr[$i] = (ord($input[$i]) - $randkey);
			$i++; 
		}
		print_r ($inputchr);
		
		$encrypted = implode('.', $inputchr) . '.' . (ord($randkey)+49);
		return $encrypted;
    }
	echo(encode("radar{}"));
?>

