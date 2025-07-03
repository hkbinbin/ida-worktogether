from idaapi import PluginForm
from PyQt5 import QtCore, QtGui, QtWidgets
import sip

class ChatPluginFormClass(PluginForm):
    def OnCreate(self, form):
        """
        Called when the widget is created
        """
        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()

        # Set window position to the bottom of the screen
        self.set_window_position()

    def PopulateForm(self):
        # Create layout
        layout = QtWidgets.QVBoxLayout()

        # Create a QTextEdit to display chat messages
        self.chat_display = QtWidgets.QTextEdit()
        self.chat_display.setReadOnly(True)  # Make it read-only to prevent users from typing directly here
        self.chat_display.setPlaceholderText("Chat messages will appear here...")
        
        # Create a QLineEdit for user input
        self.chat_input = QtWidgets.QLineEdit()
        self.chat_input.setPlaceholderText("Enter your message...")
        
        # Create a QPushButton to send the message
        self.send_button = QtWidgets.QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)
        
        # Create a button to clear chat
        self.clear_button = QtWidgets.QPushButton("Clear Chat")
        self.clear_button.clicked.connect(self.clear_chat)
        
        # Add widgets to the layout
        layout.addWidget(self.chat_display)
        layout.addWidget(self.chat_input)
        layout.addWidget(self.send_button)
        layout.addWidget(self.clear_button)
        
        # Set the layout for the form
        self.parent.setLayout(layout)

        # Connect the returnPressed signal to send_message function
        self.chat_input.returnPressed.connect(self.send_message)

    def set_window_position(self):
        """
        This function sets the window to the bottom of the screen.
        """
        screen_geometry = QtWidgets.QApplication.desktop().availableGeometry()
        screen_height = screen_geometry.height()

        # Get the window height
        window_height = self.parent.height()

        # Move the window to the bottom of the screen
        self.parent.move(0, screen_height - window_height)

    def send_message(self):
        """
        This function is called when the user clicks the 'Send' button or presses 'Enter' key.
        It appends the message to the chat display.
        """
        message = self.chat_input.text()
        if message:
            # Display the message in the chat window (prepend 'Me: ')
            self.chat_display.append(f"Me: {message}")
            self.chat_input.clear()  # Clear the input box after sending

    def clear_chat(self):
        """
        Clears the chat display
        """
        self.chat_display.clear()

    def OnClose(self, form):
        """
        Called when the widget is closed
        """
        pass


# Create and show the plugin form
plg = ChatPluginFormClass()
plg.Show("Chat Window")
