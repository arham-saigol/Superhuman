<script>
	import { WEBUI_NAME } from '$lib/stores';
</script>

<svelte:head>
	<title>Access Not Granted - {$WEBUI_NAME}</title>
</svelte:head>

<div class="min-h-screen w-full flex items-center justify-center bg-gray-50 dark:bg-black px-6">
	<div class="max-w-xl w-full rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-950 p-8">
		<h1 class="text-2xl font-semibold mb-3">Access not granted</h1>
		<p class="text-sm text-gray-600 dark:text-gray-300">
			Your account is authenticated, but this private Superhuman instance has not allowlisted your email yet.
		</p>
		<p class="text-sm text-gray-600 dark:text-gray-300 mt-3">
			Ask an operator to run <code>superhuman allow &lt;your-email&gt;</code> on the VPS.
		</p>
	</div>
</div>
