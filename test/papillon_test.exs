defmodule PapillonTest do
  use ExUnit.Case
  doctest Papillon

  test "greets the world" do
    assert Papillon.hello() == :world
  end
end
