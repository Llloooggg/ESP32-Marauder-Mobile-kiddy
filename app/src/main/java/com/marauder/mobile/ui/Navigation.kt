package com.marauder.mobile.ui

import android.app.Activity
import android.net.Uri
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.PermScanWifi
import androidx.compose.material3.Icon
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.marauder.mobile.data.AnalyzerKind
import com.marauder.mobile.data.Catalog
import com.marauder.mobile.data.ListType
import com.marauder.mobile.data.MenuAction
import com.marauder.mobile.data.MenuItem
import com.marauder.mobile.ui.components.TermsOverlay
import com.marauder.mobile.ui.screens.AboutScreen
import com.marauder.mobile.ui.screens.AnalyzerScreen
import com.marauder.mobile.ui.screens.ApDetailScreen
import com.marauder.mobile.ui.screens.ArtifactDetailScreen
import com.marauder.mobile.ui.screens.ArtifactsScreen
import com.marauder.mobile.ui.screens.ConnectScreen
import com.marauder.mobile.ui.screens.ConsoleScreen
import com.marauder.mobile.ui.screens.CrackScreen
import com.marauder.mobile.ui.screens.EvilPortalScreen
import com.marauder.mobile.ui.screens.FlashScreen
import com.marauder.mobile.ui.screens.HomeScreen
import com.marauder.mobile.ui.screens.ListScreen
import com.marauder.mobile.ui.screens.LiveActivityScreen
import com.marauder.mobile.ui.screens.MenuScreen
import com.marauder.mobile.ui.screens.SettingsScreen
import com.marauder.mobile.ui.screens.MissionScreen
import com.marauder.mobile.ui.screens.ScanScreen
import com.marauder.mobile.ui.screens.WordlistsScreen
import com.marauder.mobile.usb.UsbSerialManager
import com.marauder.mobile.vm.MarauderViewModel

/**
 * Route map. The product flow is connect → home → scan → ap index → mission id;
 * the original command tree (menu subtree, live, analyzer, list) stays reachable
 * from Home's Toolbox, so no firmware command becomes unreachable.
 */
private object Routes {
    const val CONNECT = "connect"
    const val HOME = "home"
    const val SCAN = "scan"
    const val ARTIFACTS = "artifacts"
    const val ARTIFACT = "artifact"
    const val WORDLISTS = "wordlists"
    const val CRACK = "crack"
    const val MISSION = "mission"
    const val AP = "ap"
    const val MENU = "menu"
    const val LIST = "list"
    const val CONSOLE = "console"
    const val ANALYZER = "analyzer"
    const val LIVE = "live"
    const val ABOUT = "about"
    const val SETTINGS = "settings"
    const val FLASH = "flash"
    const val EVIL_PORTAL = "evil_portal_screen"

    fun menu(id: String) = "$MENU/$id"
    fun ap(bssid: String) = "$AP/${Uri.encode(bssid)}"
    fun mission(id: Long) = "$MISSION/$id"
    fun artifact(name: String) = "$ARTIFACT/${Uri.encode(name)}"
    fun crack(name: String) = "$CRACK/${Uri.encode(name)}"
    fun list(type: ListType) = "$LIST/${type.name}"
    fun analyzer(kind: AnalyzerKind, command: String) = "$ANALYZER/${kind.name}/${Uri.encode(command)}"
    fun live(title: String, command: String) = "$LIVE/${Uri.encode(title)}/${Uri.encode(command)}"
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppRoot() {
    val vm: MarauderViewModel = viewModel()
    val nav = rememberNavController()
    val context = LocalContext.current
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(Unit) {
        vm.snackbar.collect { snackbarHostState.showSnackbar(it) }
    }

    ConnectionGate(vm, nav)

    val backStackEntry by nav.currentBackStackEntryAsState()
    val currentRoute = backStackEntry?.destination?.route
    val inProductFlow = currentRoute == Routes.HOME || currentRoute == Routes.SCAN || currentRoute == Routes.ARTIFACTS

    Scaffold(
        bottomBar = {
            if (inProductFlow) {
                NavigationBar(containerColor = MaterialTheme.colorScheme.surfaceVariant) {
                    NavigationBarItem(
                        selected = currentRoute == Routes.HOME,
                        onClick = { nav.navigate(Routes.HOME) { popUpTo(Routes.HOME); launchSingleTop = true } },
                        icon = { Icon(Icons.Filled.Home, contentDescription = "Home") },
                        label = { Text("Home") },
                        alwaysShowLabel = true,
                    )
                    NavigationBarItem(
                        selected = currentRoute == Routes.SCAN,
                        onClick = { nav.navigate(Routes.SCAN) { launchSingleTop = true } },
                        icon = { Icon(Icons.Filled.PermScanWifi, contentDescription = "Scan") },
                        label = { Text("Scan") },
                        alwaysShowLabel = true,
                    )
                    NavigationBarItem(
                        selected = currentRoute == Routes.ARTIFACTS,
                        onClick = { nav.navigate(Routes.ARTIFACTS) { launchSingleTop = true } },
                        icon = { Icon(Icons.Filled.Folder, contentDescription = "Library") },
                        label = { Text("Library") },
                        alwaysShowLabel = true,
                    )
                }
            }
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { inner ->
        val termsVisible by vm.termsVisible.collectAsState()
        Box(Modifier.fillMaxSize().padding(inner)) {
            NavHost(
                navController = nav,
                startDestination = Routes.CONNECT,
                modifier = Modifier.fillMaxSize(),
            ) {

            composable(Routes.CONNECT) {
                ConnectScreen(vm, onOpenFlash = { nav.navigate(Routes.FLASH) })
            }

            composable(Routes.HOME) {
                HomeScreen(
                    vm = vm,
                    onOpenScan = { nav.navigate(Routes.SCAN) },
                    onOpenArtifacts = { nav.navigate(Routes.ARTIFACTS) },
                    onOpenWordlists = { nav.navigate(Routes.WORDLISTS) },
                    onOpenMission = { id -> nav.navigate(Routes.mission(id)) },
                    onOpenMenu = { id -> nav.navigate(Routes.menu(id)) },
                    onOpenConsole = { nav.navigate(Routes.CONSOLE) },
                    onOpenFlash = { nav.navigate(Routes.FLASH) },
                    onOpenAbout = { nav.navigate(Routes.ABOUT) },
                    onOpenSettings = { nav.navigate(Routes.SETTINGS) },
                    onOpenCatalogItem = { item -> handleAction(item, nav, vm) },
                    onDisconnect = { vm.disconnect() },
                )
            }

            composable(Routes.SCAN) {
                ScanScreen(
                    vm = vm,
                    onBack = { nav.popBackStack() },
                    onOpenAp = { bssid -> nav.navigate(Routes.ap(bssid)) },
                    onOpenMission = { id -> nav.navigate(Routes.mission(id)) },
                )
            }

            composable(Routes.ARTIFACTS) {
                ArtifactsScreen(
                    vm = vm,
                    onBack = { nav.popBackStack() },
                    onOpenArtifact = { name -> nav.navigate(Routes.artifact(name)) },
                    onOpenWordlists = { nav.navigate(Routes.WORDLISTS) },
                )
            }

            composable(
                route = "${Routes.ARTIFACT}/{name}",
                arguments = listOf(navArgument("name") { type = NavType.StringType }),
            ) { entry ->
                ArtifactDetailScreen(
                    artifactName = Uri.decode(entry.arguments?.getString("name").orEmpty()),
                    vm = vm,
                    onBack = { nav.popBackStack() },
                    onOpenCrack = { name -> nav.navigate(Routes.crack(name)) },
                )
            }

            composable(Routes.WORDLISTS) {
                WordlistsScreen(vm = vm, onBack = { nav.popBackStack() })
            }

            composable(
                route = "${Routes.CRACK}/{name}",
                arguments = listOf(navArgument("name") { type = NavType.StringType }),
            ) { entry ->
                CrackScreen(
                    artifactName = Uri.decode(entry.arguments?.getString("name").orEmpty()),
                    onBack = { nav.popBackStack() },
                    onOpenWordlists = { nav.navigate(Routes.WORDLISTS) },
                )
            }

            composable(
                route = "${Routes.AP}/{bssid}",
                arguments = listOf(navArgument("bssid") { type = NavType.StringType }),
            ) { entry ->
                ApDetailScreen(
                    apBssid = entry.arguments?.getString("bssid").orEmpty(),
                    vm = vm,
                    onBack = { nav.popBackStack() },
                    onOpenMission = { id -> nav.navigate(Routes.mission(id)) },
                    onOpenLive = { title, cmd -> nav.navigate(Routes.live(title, cmd)) },
                    onOpenAnalyzer = { cmd, kind -> nav.navigate(Routes.analyzer(kind, cmd)) },
                )
            }

            composable(
                route = "${Routes.MISSION}/{id}",
                arguments = listOf(navArgument("id") { type = NavType.LongType }),
            ) { entry ->
                MissionScreen(
                    missionId = entry.arguments?.getLong("id") ?: -1L,
                    vm = vm,
                    onBack = { nav.popBackStack() },
                )
            }

            composable(
                route = "${Routes.MENU}/{id}",
                arguments = listOf(navArgument("id") { type = NavType.StringType }),
            ) { entry ->
                val id = entry.arguments?.getString("id") ?: Catalog.ROOT
                MenuScreen(
                    screenId = id,
                    vm = vm,
                    onItemClick = { item -> handleAction(item, nav, vm) },
                    onBack = { nav.popBackStack() },
                    onOpenConsole = { nav.navigate(Routes.CONSOLE) },
                    onOpenAbout = { nav.navigate(Routes.ABOUT) },
                    onOpenSettings = { nav.navigate(Routes.SETTINGS) },
                    onDisconnect = { vm.disconnect() },
                )
            }

            composable(
                route = "${Routes.LIST}/{type}",
                arguments = listOf(navArgument("type") { type = NavType.StringType }),
            ) { entry ->
                val type = runCatching { ListType.valueOf(entry.arguments?.getString("type").orEmpty()) }
                    .getOrDefault(ListType.ACCESS_POINTS)
                ListScreen(
                    type = type,
                    vm = vm,
                    onBack = { nav.popBackStack() },
                    onOpenLive = { title, cmd -> nav.navigate(Routes.live(title, cmd)) },
                )
            }

            composable(Routes.CONSOLE) {
                ConsoleScreen(vm = vm, onBack = { nav.popBackStack() })
            }

            composable(Routes.ABOUT) {
                AboutScreen(onBack = { nav.popBackStack() }, onShowTerms = { vm.showTerms() })
            }

            composable(Routes.SETTINGS) {
                SettingsScreen(
                    vm = vm,
                    onBack = { nav.popBackStack() },
                    onOpenWordlists = { nav.navigate(Routes.WORDLISTS) },
                    onOpenAbout = { nav.navigate(Routes.ABOUT) },
                )
            }

            composable(Routes.FLASH) {
                FlashScreen(vm = vm, onBack = { nav.popBackStack() })
            }

            composable(Routes.EVIL_PORTAL) {
                EvilPortalScreen(vm = vm, onBack = { nav.popBackStack() })
            }

            composable(
                route = "${Routes.ANALYZER}/{kind}/{cmd}",
                arguments = listOf(
                    navArgument("kind") { type = NavType.StringType },
                    navArgument("cmd") { type = NavType.StringType },
                ),
            ) { entry ->
                val kind = runCatching { AnalyzerKind.valueOf(entry.arguments?.getString("kind").orEmpty()) }
                    .getOrDefault(AnalyzerKind.WIFI)
                val command = Uri.decode(entry.arguments?.getString("cmd").orEmpty())
                AnalyzerScreen(command = command, kind = kind, vm = vm, onBack = { nav.popBackStack() })
            }

            composable(
                route = "${Routes.LIVE}/{title}/{cmd}",
                arguments = listOf(
                    navArgument("title") { type = NavType.StringType },
                    navArgument("cmd") { type = NavType.StringType },
                ),
            ) { entry ->
                val title = Uri.decode(entry.arguments?.getString("title").orEmpty())
                val command = Uri.decode(entry.arguments?.getString("cmd").orEmpty())
                LiveActivityScreen(title = title, command = command, vm = vm, onBack = { nav.popBackStack() })
            }
            }

            // The authorised-use gate sits on top of everything: nothing is usable
            // until the user has accepted it for this install.
            if (termsVisible) {
                TermsOverlay(
                    onAccept = { vm.acceptTerms() },
                    onExit = { (context as? Activity)?.finish() },
                )
            }
        }
    }
}

/**
 * Steers the user between the connect screen and the product root as the link goes
 * down/up. Missions survive navigation (they are supervised by the ViewModel), so
 * only the connection itself forces a redirect here.
 */
@Composable
private fun ConnectionGate(vm: MarauderViewModel, nav: NavHostController) {
    val status by vm.status.collectAsState()
    val backStackEntry by nav.currentBackStackEntryAsState()
    val currentRoute = backStackEntry?.destination?.route

    LaunchedEffect(status, currentRoute) {
        when (status) {
            UsbSerialManager.Status.CONNECTED -> {
                if (currentRoute == Routes.CONNECT) {
                    nav.navigate(Routes.HOME) {
                        popUpTo(Routes.CONNECT) { inclusive = true }
                        launchSingleTop = true
                    }
                }
            }
            UsbSerialManager.Status.DISCONNECTED -> {
                // Don't yank the user off the flasher: it intentionally runs while the
                // normal serial session is down (it holds the port itself).
                if (currentRoute != null && currentRoute != Routes.CONNECT && currentRoute != Routes.FLASH) {
                    nav.navigate(Routes.CONNECT) {
                        popUpTo(0) { inclusive = true }
                        launchSingleTop = true
                    }
                }
            }
            else -> {}
        }
    }
}

/** Advanced-tree action routing: submenus, lists, analyzers and raw live commands. */
private fun handleAction(
    item: MenuItem,
    nav: NavHostController,
    vm: MarauderViewModel,
) {
    when (val action = item.action) {
        is MenuAction.Submenu -> nav.navigate(Routes.menu(action.id))
        is MenuAction.Send -> nav.navigate(Routes.live(item.title, action.command))
        is MenuAction.OpenList -> {
            vm.refreshList(action.type)
            nav.navigate(Routes.list(action.type))
        }
        is MenuAction.OpenAnalyzer -> nav.navigate(Routes.analyzer(action.kind, action.command))
        MenuAction.OpenConsole -> nav.navigate(Routes.CONSOLE)
        MenuAction.OpenFlash -> nav.navigate(Routes.FLASH)
        MenuAction.OpenEvilPortal -> nav.navigate(Routes.EVIL_PORTAL)
    }
}
