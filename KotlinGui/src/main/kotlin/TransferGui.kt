import java.awt.BorderLayout
import java.awt.Desktop
import java.awt.Dimension
import java.awt.FlowLayout
import java.io.File
import java.util.concurrent.TimeUnit
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JFileChooser
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTabbedPane
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.SwingUtilities
import javax.swing.UIManager

class TransferGui : JFrame("Transfert UDP/DTLS") {
    // L'interface Kotlin ne transfere pas directement les octets.
    // Elle lance les executables C++ client.exe et Server.exe avec les bons arguments.
    private val root = findProjectRoot()
    private val clientExe = File(root, "client/x64/Debug/client.exe")
    private val serverExe = File(root, "Server/x64/Debug/Server.exe")
    private var serverProcess: Process? = null

    init {
        defaultCloseOperation = EXIT_ON_CLOSE
        size = Dimension(760, 520)
        setLocationRelativeTo(null)

        val tabs = JTabbedPane()
        tabs.addTab("Envoyer fichier", sendTab())
        tabs.addTab("Recevoir fichier", receiveTab())
        tabs.addTab("Serveur", serverTab())
        contentPane.add(tabs)
    }

    private fun sendTab(): JPanel {
        // Page A -> serveur: choix du fichier source et appel du client en mode put.
        val ip = JTextField("127.0.0.1")
        val port = JTextField("4444")
        val sendFile = JTextField()
        val log = logArea()

        val chooseSend = JButton("Choisir")
        chooseSend.addActionListener { chooseOpen(sendFile) }

        val send = JButton("Envoyer fichier")
        send.addActionListener {
            val file = sendFile.text.trim()
            if (file.isBlank()) {
                message("Choisis un fichier a envoyer.")
            } else {
                runClient(listOf(ip.text.trim(), port.text.trim(), "put", file), log)
            }
        }

        val form = JPanel()
        form.layout = javax.swing.BoxLayout(form, javax.swing.BoxLayout.Y_AXIS)
        form.add(row("IP serveur", ip))
        form.add(row("Port", port))
        form.add(row("Fichier a envoyer", sendFile, chooseSend))
        form.add(buttons(send))

        return screen(form, log)
    }

    private fun receiveTab(): JPanel {
        // Page serveur -> B: choix du fichier destination et appel du client en mode get.
        val ip = JTextField("127.0.0.1")
        val port = JTextField("4444")
        val recvFile = JTextField(File(root, "fichier_recu.bin").absolutePath)
        val log = logArea()
        val receivedInfo = JLabel("Aucun fichier recu pour le moment.")
        val openReceived = JButton("Ouvrir fichier recu")
        val openFolder = JButton("Ouvrir dossier")
        openReceived.isEnabled = false

        val chooseRecv = JButton("Choisir")
        chooseRecv.addActionListener { chooseSave(recvFile) }

        openReceived.addActionListener {
            val file = File(recvFile.text.trim())
            if (file.exists()) {
                openFile(file)
            } else {
                message("Le fichier recu n'existe pas encore.")
            }
        }

        openFolder.addActionListener {
            val file = File(recvFile.text.trim())
            val folder = file.parentFile ?: root
            if (folder.exists()) Desktop.getDesktop().open(folder)
        }

        val receive = JButton("Recevoir fichier")
        receive.addActionListener {
            val file = recvFile.text.trim()
            if (file.isBlank()) {
                message("Choisis le fichier de destination.")
            } else {
                val destination = File(file)
                val parent = destination.parentFile
                if (parent != null && !parent.exists() && !parent.mkdirs()) {
                    message("Impossible de creer le dossier de destination.")
                    return@addActionListener
                }
                if (destination.exists() && !destination.delete()) {
                    // Protection contre la confusion: si l'ancienne copie ne peut pas
                    // etre supprimee, on n'ouvre pas accidentellement l'ancien fichier.
                    message("Ferme l'ancien fichier recu avant de relancer la reception.")
                    append(log, "Ancienne copie impossible a effacer: ${destination.absolutePath}\n")
                    return@addActionListener
                }
                openReceived.isEnabled = false
                receivedInfo.text = "Reception en cours..."
                runClient(listOf(ip.text.trim(), port.text.trim(), "get", file), log) { exitCode ->
                    if (exitCode == 0 && destination.exists()) {
                        receivedInfo.text = "Dernier fichier recu: ${destination.name} (${destination.length()} octets)"
                        openReceived.isEnabled = true
                        append(log, "Fichier pret a ouvrir: ${destination.absolutePath}\n")
                    } else {
                        receivedInfo.text = "Reception echouee: aucun nouveau fichier disponible."
                        openReceived.isEnabled = false
                    }
                }
            }
        }

        val form = JPanel()
        form.layout = javax.swing.BoxLayout(form, javax.swing.BoxLayout.Y_AXIS)
        form.add(row("IP serveur", ip))
        form.add(row("Port", port))
        form.add(row("Enregistrer sous", recvFile, chooseRecv))
        form.add(buttons(receive, openReceived, openFolder))
        form.add(receivedInfo)

        return screen(form, log)
    }

    private fun serverTab(): JPanel {
        // Page serveur: demarre/arrete le processus Server.exe qui attend les clients DTLS.
        val port = JTextField("4444")
        val log = logArea()
        val start = JButton("Demarrer serveur")
        val stop = JButton("Arreter serveur")
        val openFolder = JButton("Ouvrir dossier")
        val clearFile = JButton("Effacer fichier stocke")
        stop.isEnabled = false

        start.addActionListener {
            if (serverProcess?.isAlive == true) return@addActionListener
            if (!serverExe.exists()) {
                append(log, "Server.exe introuvable: ${serverExe.absolutePath}\n")
                return@addActionListener
            }
            val cmd = listOf(serverExe.absolutePath, port.text.trim())
            Thread {
                SwingUtilities.invokeLater {
                    start.isEnabled = false
                    stop.isEnabled = true
                }
                try {
                    append(log, "\n> ${cmd.joinToString(" ")}\n")
                    val process = ProcessBuilder(cmd).directory(serverExe.parentFile).redirectErrorStream(true).start()
                    serverProcess = process
                    process.inputStream.bufferedReader().forEachLine { append(log, "$it\n") }
                    append(log, "Serveur termine: code ${process.waitFor()}\n")
                } catch (ex: Exception) {
                    append(log, "Erreur serveur: ${ex.message}\n")
                } finally {
                    serverProcess = null
                    SwingUtilities.invokeLater {
                        start.isEnabled = true
                        stop.isEnabled = false
                    }
                }
            }.start()
        }

        stop.addActionListener {
            serverProcess?.destroy()
            if (serverProcess?.waitFor(2, TimeUnit.SECONDS) == false) {
                serverProcess?.destroyForcibly()
            }
        }

        openFolder.addActionListener {
            if (serverExe.parentFile.exists()) Desktop.getDesktop().open(serverExe.parentFile)
        }

        clearFile.addActionListener {
            val stored = File(serverExe.parentFile, "received_file.bin")
            append(log, if (stored.exists() && stored.delete()) "Fichier stocke efface.\n" else "Aucun fichier stocke a effacer.\n")
        }

        val form = JPanel()
        form.layout = javax.swing.BoxLayout(form, javax.swing.BoxLayout.Y_AXIS)
        form.add(row("Port", port))
        form.add(buttons(start, stop, openFolder, clearFile))
        form.add(JLabel("Fichier serveur: ${File(serverExe.parentFile, "received_file.bin").absolutePath}"))

        return screen(form, log)
    }

    private fun runClient(args: List<String>, log: JTextArea, onComplete: ((Int) -> Unit)? = null) {
        // Lance client.exe dans un thread separe pour garder l'interface reactive.
        // args contient: IP, port, mode put/get, chemin du fichier.
        if (!clientExe.exists()) {
            append(log, "client.exe introuvable: ${clientExe.absolutePath}\n")
            SwingUtilities.invokeLater { onComplete?.invoke(-1) }
            return
        }
        val cmd = listOf(clientExe.absolutePath) + args
        Thread {
            var exitCode = -1
            try {
                append(log, "\n> ${cmd.joinToString(" ")}\n")
                val process = ProcessBuilder(cmd).directory(clientExe.parentFile).redirectErrorStream(true).start()
                process.inputStream.bufferedReader().forEachLine { append(log, "$it\n") }
                exitCode = process.waitFor()
                append(log, "Client termine: code $exitCode\n")
            } catch (ex: Exception) {
                append(log, "Erreur client: ${ex.message}\n")
            } finally {
                SwingUtilities.invokeLater { onComplete?.invoke(exitCode) }
            }
        }.start()
    }

    private fun row(label: String, field: JTextField, button: JButton? = null): JPanel {
        val panel = JPanel(BorderLayout(8, 0))
        panel.border = BorderFactory.createEmptyBorder(4, 0, 4, 0)
        panel.add(JLabel(label).apply { preferredSize = Dimension(130, 26) }, BorderLayout.WEST)
        panel.add(field, BorderLayout.CENTER)
        if (button != null) panel.add(button, BorderLayout.EAST)
        return panel
    }

    private fun buttons(vararg buttons: JButton): JPanel {
        val panel = JPanel(FlowLayout(FlowLayout.LEFT))
        buttons.forEach { panel.add(it) }
        return panel
    }

    private fun screen(top: JPanel, log: JTextArea): JPanel {
        val panel = JPanel(BorderLayout(8, 8))
        panel.border = BorderFactory.createEmptyBorder(12, 12, 12, 12)
        panel.add(top, BorderLayout.NORTH)
        panel.add(JScrollPane(log), BorderLayout.CENTER)
        return panel
    }

    private fun logArea() = JTextArea().apply {
        isEditable = false
        lineWrap = true
        wrapStyleWord = true
    }

    private fun append(log: JTextArea, text: String) {
        SwingUtilities.invokeLater {
            log.append(text)
            log.caretPosition = log.document.length
        }
    }

    private fun chooseOpen(target: JTextField) {
        val chooser = JFileChooser()
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            target.text = chooser.selectedFile.absolutePath
        }
    }

    private fun chooseSave(target: JTextField) {
        val chooser = JFileChooser()
        chooser.selectedFile = File(target.text)
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            target.text = chooser.selectedFile.absolutePath
        }
    }

    private fun openFile(file: File) {
        try {
            Desktop.getDesktop().open(file)
        } catch (ex: Exception) {
            message("Impossible d'ouvrir le fichier: ${ex.message}")
        }
    }

    private fun message(text: String) = JOptionPane.showMessageDialog(this, text)

    private fun findProjectRoot(): File {
        var dir: File? = File(System.getProperty("user.dir")).canonicalFile
        while (dir != null) {
            if (File(dir, "client/x64/Debug/client.exe").exists() || File(dir, "client/client.cpp").exists()) {
                return dir
            }
            dir = dir.parentFile
        }
        return File(System.getProperty("user.dir")).canonicalFile.parentFile
    }
}

fun main() {
    UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName())
    SwingUtilities.invokeLater { TransferGui().isVisible = true }
}
