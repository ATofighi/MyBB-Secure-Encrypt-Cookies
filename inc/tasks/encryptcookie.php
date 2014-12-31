<?php
function task_encryptcookie($task)
{
	global $db, $lang;

	$lang->load("encryptcookie");

	$db->delete_query("cookies", "time < ".(TIME_NOW-604800)); // Everything older than 7 days is deleted
	$log = $db->affected_rows();

	add_task_log($task, $lang->sprintf($lang->encryptcookie_deleted, $log));
}