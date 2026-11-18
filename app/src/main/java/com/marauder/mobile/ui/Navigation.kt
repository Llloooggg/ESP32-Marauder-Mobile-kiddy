package com.marauder.mobile.ui

import android.net.Uri
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
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
import com.marauder.mobile.ui.screens.AboutScreen
import com.marauder.mobile.ui.screens.AnalyzerScreen
import com.marauder.mobile.ui.screens.ApDetailScreen
import com.marauder.mobile.ui.screens.ConnectScreen
import com.marauder.mobile.ui.screens.ConsoleScreen
import com.marauder.mobile.ui.screens.EvilPortalScreen
import com.marauder.mobile.ui.screens.FlashScreen
import com.marauder.mobile.ui.screens.HomeScreen
import com.marauder.mobile.ui.screens.ListScreen
import com.marauder.mobile.ui.screens.LiveActivityScreen
import com.marauder.mobile.ui.screens.MenuScreen
import com.marauder.mobile.ui.screens.MissionScreen
import com.marauder.mobile.ui.screens.ScanScreen
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
    const val MISSION = "mission"
    const val AP = "ap"
    const val MENU = "menu"
    const val LIST = "list"
    const val CONSOLE = "console"
    const val ANALYZER = "analyzer"
    const val LIVE = "live"
    const val ABOUT = "about"
    const val FLASH = "flash"
    const val EVIL_PORTAL = "evil_portal_screen"

    fun menu(id: String) = "$MENU/$id"
    fun ap(index: Int) = "$AP/$index"
    fun mission(id: Long) = "$MISSION/$id"
    fun list(type: ListType) = "$LIST/${type.name}"
    fun analyzer(kind: AnalyzerKind, command: String) = "$ANALYZER/${kind.name}/${Uri.encode(command)}"
    fun live(title: String, command: String) = "$LIVE/${Uri.encode(title)}/${Uri.encode(command)}"
}

@Composable
fun AppRoot() {
    val vm: MarauderViewModel = viewModel()
    val nav = rememberNavController()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(Unit) {
        vm.snackbar.collect { snackbarHostState.showSnackbar(it) }
    }

    ConnectionGate(vm, nav)

    Box(Modifier.fillMaxSize()) {
        NavHost(navController = nav, startDestination = Routes.CONNECT) {

            composable(Routes.CONNECT) {
                ConnectScreen(vm, onOpenFlash = { nav.navigate(Routes.FLASH) })
            }

            composable(Routes.HOME) {
                HomeScreen(
                    vm = vm,
                    onOpenScan = { nav.navigate(Routes.SCAN) },
                    onOpenMission = { id -> nav.navigate(Routes.mission(id)) },
                    onOpenMenu = { id -> nav.navigate(Routes.menu(id)) },
                    onOpenConsole = { nav.navigate(Routes.CONSOLE) },
                    onOpenFlash = { nav.navigate(Routes.FLASH) },
                    onOpenAbout = { nav.navigate(Routes.ABOUT) },
                    onDisconnect = { vm.disconnect() },
                )
            }

            composable(Routes.SCAN) {
                ScanScreen(
                    vm = vm,
                    onBack = { nav.popBackStack() },
                    onOpenAp = { index -> nav.navigate(Routes.ap(index)) },
                    onOpenMission = { id -> nav.navigate(Routes.mission(id)) },
                )
            }

            composable(
                route = "${Routes.AP}/{index}",
                arguments = listOf(navArgument("index") { type = NavType.IntType }),
            ) { entry ->
                ApDetailScreen(
                    apIndex = entry.arguments?.getInt("index") ?: -1,
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
                AboutScreen(onBack = { nav.popBackStack() })
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

        SnackbarHost(
            hostState = snackbarHostState,
            modifier = Modifier.align(Alignment.BottomCenter),
        )
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
