$(document).ready(function(){
	$login = $('.login');

	$('.login-trigger').click(function(){
		$login.slideDown(250);
		$('.error').fadeOut(100);
	});
	$('.close').click(function(){
		$login.slideUp(250);
	});
});