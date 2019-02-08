defmodule Papillon.NotificationServer do
	require Logger

	# XXX: Erlang supervision; start new servers with proper linkage
	def main() do
		me = self()
		listener = spawn(fn -> accept_ns(me) end)
		recv_loop
	end
	
	defp recv_loop() do
		receive do
			{:newClient, clientPid} ->
				Logger.debug("New client: #{inspect clientPid}")
				recv_loop()
			x ->
				Logger.debug("Huh?")
				IO.inspect(x)
				recv_loop()
		end
	end

	def accept_ns(parent) do
		accept_ns(parent, 1863) # default msnp port
	end

	def accept_ns(parent, port) do
		# using magic names per https://elixir-lang.org/getting-started/mix-otp/task-and-gen-tcp.html
		# i do wonder about the viability of this though
		{:ok, socket} = :gen_tcp.listen(port, [:binary,
			packet: :line, # XXX: erlang docs are horrible about what these things mean
			active: false, reuseaddr: true])
		Logger.info("NS listening")
		listen_ns(parent, socket)
	end

	# Notification server
	defp listen_ns(parent, socket) do
		{:ok, client} = :gen_tcp.accept(socket)
		pid = spawn(fn -> serve_ns(parent, client, %{}) end)
		send(parent, {:newClient, pid})
		listen_ns(parent, socket)
	end

	# the idea is we can keep the state of the connection in clientState
	# the serve "loop" will process each command and return a new state
	# for the next command
	# hopefully it works - it's functional, i hope
	defp serve_ns(parent, client, clientState) do
		# temp debug thing
		{readStatus, line} = :gen_tcp.recv(client, 0)
		case readStatus do
			:ok ->
				serve_ns_ok(parent, line, client, clientState)
			_ ->
				send(parent, {:clientFailed, self()})
		end
	end

	defp serve_ns_ok(parent, line, client, clientState) do
		Logger.debug(line)
		# let's split this into tokens
		splitLine = String.split(line)
		# XXX: This loop probably needs rewriting
		case splitLine do
			["VER", id | protocols] ->
				latestProto = hd(protocols)
				# XXX: MSNIM 4.6 hangs on SYN if we try to use MSNP7...
				#write_line(client, "VER #{id} #{latestProto}\r\n")
				write_line(client, "VER #{id} MSNP6\r\n")
				serve_ns(parent, client, clientState)
			["CVR", id | _] ->
				# Dummy response
				write_line(client, "CVR #{id} 1.0.0000, 1.0.0000 1.0.0000 about:blank about:blank")
				serve_ns(parent, client, clientState)
			["INF", id] ->
				# We only support MD5 for now
				write_line(client, "INF #{id} MD5\r\n")
				serve_ns(parent, client, clientState)
			["USR", id, "MD5", "I", passport] ->
				# This would be the point that if we were a
				# dispatch server, we could transfer to a real
				# notitifcation server.
				# XXX: Actually validate and attach salt et al
				write_line(client, "USR #{id} MD5 S SALT\r\n")
				newState = Map.merge(clientState, %{:passport => passport})
				serve_ns(parent, client, newState)
			["USR", id, "MD5", "S", pwhash] ->
				# Happy hour
				# XXX: Actually validate the salted PW
				# The 1 at the end means you're a validated account
				write_line(client, "USR #{id} OK #{Map.get(clientState, :passport)} HelloWorld 1\r\n")
				serve_ns(parent, client, clientState)
			["CHG", id, newStatus] ->
				write_line(client, "CHG #{id} #{newStatus}\r\n") # XXX: escargot w/ 3.6 appends a 0 here?
				# XXX: Actually keep track of state and send the initial ILNs
				serve_ns(parent, client, clientState)
			["LSG", id] ->
				send_groups(client, id, 0, Map.get(clientState, :passport))
				serve_ns(parent, client, clientState)
			["LST", id, "FL"] ->
				# XXX: better way for generation ID stuff?
				send_forward_list(client, id, 0, Map.get(clientState, :passport))
				serve_ns(parent, client, clientState)
			["LST", id, "RL"] ->
				send_reverse_list(client, id, 0, Map.get(clientState, :passport))
				serve_ns(parent, client, clientState)
			["LST", id, "AL"] ->
				send_allow_list(client, id, 0, Map.get(clientState, :passport))
				serve_ns(parent, client, clientState)
			["LST", id, "BL"] ->
				send_block_list(client, id, 0, Map.get(clientState, :passport))
				serve_ns(parent, client, clientState)
			["SYN", id, genId] ->
				# We're supposed to diff the changes per generation (or send all for 0)
				newGenId = elem(Integer.parse(genId), 0) + 1
				# Escargot seems to buffer messages, but MSN 3.6 and 4.6 are OK with this?
				# Is this order sensitive?
				write_line(client, "SYN #{id} #{newGenId}\r\n")
				send_groups(client, id, newGenId, Map.get(clientState, :passport))
				send_forward_list(client, id, newGenId, Map.get(clientState, :passport))
				send_allow_list(client, id, newGenId, Map.get(clientState, :passport))
				send_block_list(client, id, newGenId, Map.get(clientState, :passport))
				send_reverse_list(client, id, newGenId, Map.get(clientState, :passport))
				write_line(client, "GTC #{id} #{newGenId} A\r\n")
				write_line(client, "BLP #{id} #{newGenId} AL\r\n")
				serve_ns(parent, client, clientState)
			["PNG"] ->
				write_line(client, "QNG\r\n")
				serve_ns(parent, client, clientState)
			["OUT"] ->
				write_line(client, "OUT\r\n")
				send(parent, {:clientDisconnect, self()})
				:gen_tcp.close(client)
			[_, id] ->
				write_line(client, "500 #{id}\r\n")
				serve_ns(parent, client, clientState)
			[_, id | _] ->
				write_line(client, "500 #{id}\r\n")
				serve_ns(parent, client, clientState)
		end
	end

	# XXX: Actually.... have a list
	# The format for the numbers is generation of list, current item, count
	defp send_groups(client, seqId, genId, passport) do
		# TODO: Actually.... return valid data
		write_line(client, "LSG #{seqId} #{genId} 0 0 0 wow 0\r\n")
	end

	defp send_forward_list(client, seqId, genId, passport) do
		# write_line(client, "LST #{seqIdid} FL #{newGenId} 1 1 example@example.com Example user 0\r\n")
		write_line(client, "LST #{seqId} FL #{genId} 0 0\r\n")
	end

	defp send_allow_list(client, seqId, genId, passport) do
		write_line(client, "LST #{seqId} AL #{genId} 0 0\r\n")
	end

	defp send_block_list(client, seqId, genId, passport) do
		write_line(client, "LST #{seqId} BL #{genId} 0 0\r\n")
	end

	defp send_reverse_list(client, seqId, genId, passport) do
		write_line(client, "LST #{seqId} RL #{genId} 0 0\r\n")
	end

	defp write_line(client, line) do
		:gen_tcp.send(client, line)
	end
end
