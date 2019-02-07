defmodule Papillon do
	require Logger
	def accept_ns(port) do
		# using magic names per https://elixir-lang.org/getting-started/mix-otp/task-and-gen-tcp.html
		# i do wonder about the viability of this though
		{:ok, socket} = :gen_tcp.listen(port, [:binary, packet: :line, active: false, reuseaddr: true])
		Logger.info("NS listening")
		listen_ns(socket)
	end

	# Notification server
	defp listen_ns(socket) do
		{:ok, client} = :gen_tcp.accept(socket)
		serve_ns(client, %{})
		listen_ns(socket)
	end

	# the idea is we can keep the state of the connection in clientState
	# the serve "loop" will process each command and return a new state
	# for the next command
	# hopefully it works - it's functional, i hope
	defp serve_ns(client, clientState) do
		# temp debug thing
		line = client
			|> read_line()
		Logger.debug(line)
		# let's split this into tokens
		splitLine = String.split(line)
		# XXX: This loop probably needs rewriting
		newState = case splitLine do
			["VER" | _] ->
				# Naive server sends back what we got
				write_line(client, line)
				clientState
			["INF", id] ->
				# We only support MD5 for now
				write_line(client, "INF #{id} MD5\r\n")
				clientState
			["USR", id, "MD5", "I", passport] ->
				# This would be the point that if we were a
				# dispatch server, we could transfer to a real
				# notitifcation server.
				# XXX: Actually validate and attach salt et al
				write_line(client, "USR #{id} MD5 S SALT\r\n")
				Map.merge(clientState, %{:passport => passport})
			["USR", id, "MD5", "S", pwhash] ->
				# Happy hour
				# XXX: Actually validate the salted PW
				# The 1 at the end means you're a validated account
				write_line(client, "USR #{id} OK #{Map.get(clientState, :passport)} HelloWorld 1\r\n")
				clientState
			["CHG", id, newStatus] ->
				write_line(client, "CHG #{id} #{newStatus}\r\n") # XXX: escargot w/ 3.6 appends a 0 here?
				# XXX: Actually keep track of state and send the initial ILNs
				clientState
			["LST", id, listType] ->
				# XXX: Actually.... have a list
				# The format for the numbers is generation of list, current item, count
				write_line(client, "LST #{id} #{listType} 0 0 0\r\n")
				clientState
			["SYN", id, genId] ->
				# genId == 0, sync everything
				newGenId = hd(Integer.parse(genId)) + 1
				write_line(client, "SYN #{id} #{newGenId}\r\n")
				write_line(client, "GTC #{id} #{newGenId} A\r\n")
				write_line(client, "BLP #{id} #{newGenId} AL\r\n")
				write_line(client, "LSG #{id} #{newGenId} 0 0 0 Group 0\r\n")
				write_line(client, "LST #{id} FL #{newGenId} 0 0\r\n")
				write_line(client, "LST #{id} AL #{newGenId} 0 0\r\n")
				write_line(client, "LST #{id} BL #{newGenId} 0 0\r\n")
				write_line(client, "LST #{id} RL #{newGenId} 0 0\r\n")
				clientState
			["PNG"] ->
				write_line(client, "QNG\r\n")
				clientState
			_ ->
				write_line(client, "500\r\n")
				clientState
		end
		# nothing is implemented, haha
		serve_ns(client, newState)
	end

	defp read_line (client) do
		{:ok, data} = :gen_tcp.recv(client, 0)
		data
	end

	defp write_line(client, line) do
		:gen_tcp.send(client, line)
	end
end
