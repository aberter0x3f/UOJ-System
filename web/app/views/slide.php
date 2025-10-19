<?php
	$content_p = strpos($content, "\n");
	$slide_config = substr($content, 0, $content_p);
	$slide_content = substr($content, $content_p + 1);

	$slide_config = json_decode($slide_config, true);
	if ($slide_config === null) {
		die('error');
	}

	if (!isset($slide_config['theme'])) {
		$slide_config['theme'] = 'moon';
	}
?>
<!DOCTYPE html>
<html lang="zh-cn">
	<head>
		<meta charset="utf-8">

		<title><?= isset($PageTitle) ? $PageTitle : UOJConfig::$data['profile']['oj-name-short'] ?> - <?= isset($PageMainTitle) ? $PageMainTitle : UOJConfig::$data['profile']['oj-name'] ?></title>

		<meta name="apple-mobile-web-app-capable" content="yes" />
		<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent" />

		<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, minimal-ui">

		<?= HTML::css_link('/css/reveal/reveal.css') ?>
		<link rel="stylesheet" type="text/css" href="<?= HTML::url('/css/reveal/theme/'.HTML::escape($slide_config['theme']).'.css') ?>" id="theme">

		<!-- Code syntax highlighting -->
		<?= HTML::css_link('/css/prism-dark.css') ?>

		<!-- Printing and PDF exports -->
		<script>
			var link = document.createElement('link');
			link.rel = 'stylesheet';
			link.type = 'text/css';
			link.href = window.location.search.match(/print-pdf/gi) ? '<?= HTML::url('/css/reveal/print/pdf.css') ?>' : '<?= HTML::url('/css/reveal/print/paper.css') ?>';
			document.getElementsByTagName('head')[0].appendChild(link);
		</script>

		<!--[if lt IE 9]>
			<script src="<?= HTML::url('/js/html5shiv.js') ?>"></script>
		<![endif]-->
	</head>
	<body>
		<div class="reveal">
			<div class="slides"><?= $slide_content ?></div>
		</div>

		<script src="<?= HTML::url('/js/head.min.js') ?>"></script>
		<script src="<?= HTML::url('/js/reveal.js') ?>"></script>
		<script src="<?= HTML::url('/js/prism.js') ?>" data-manual></script>

		<script>
		window.MathJax = {
			output: {
				font: 'mathjax-tex',
				fontPath: '<?= HTML::url('/js/mathjax/tex-font') ?>'
			},
			tex: {
				inlineMath: [['$', '$']],
				displayMath: [['$$', '$$']],
				processEscapes: true
			},
			// 针对 reveal.js 的特殊处理，确保在幻灯片切换后能重新渲染数学公式
			startup: {
				ready: function () {
					MathJax.startup.defaultReady();
					// reveal.js 会在 'slidechanged' 事件时触发
					Reveal.addEventListener('slidechanged', function(event) {
						MathJax.typesetPromise();
					});
				}
			}
		};
		</script>

		<script src="<?= HTML::url('/js/mathjax/dist/tex-chtml-nofont.js') ?>"></script>

		<script type="text/javascript">
			Reveal.initialize({
				controls: true,
				progress: true,
				history: true,
				center: true,
				help: true,

				transition: 'slide',

				dependencies: [
					{ src: '<?= HTML::url('/js/classList.js') ?>', condition: function() { return !document.body.classList; } },
					{ src: '<?= HTML::url('/js/reveal/plugin/prism/prism.js') ?>', async: true, condition: function() { return !!document.querySelector( 'pre code' ); } },
					{ src: '<?= HTML::url('/js/reveal/plugin/zoom-js/zoom.js') ?>', async: true },
					{ src: '<?= HTML::url('/js/reveal/plugin/notes/notes.js') ?>', async: true },
				]
			});
		</script>
	</body>
</html>
