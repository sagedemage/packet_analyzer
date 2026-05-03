<script setup lang="ts">
const { data: packet_data } = await useFetch<{ Destination: Array<string>, Source: Array<string>, Info: Array<string>, Length: Array<number>, Num: Array<number>, Protocol: Array<string>, }>('http://127.0.0.1:5000/get-data-of-pcapng-file')

const packet_data_s = packet_data.value
const source  = packet_data_s!.Source
const destination  = packet_data_s!.Destination
const info  = packet_data_s!.Info
const length  = packet_data_s!.Length
const num  = packet_data_s!.Num
const proto  = packet_data_s!.Protocol
</script>

<template>
  <span>
    <slot />
    <table>
      <tbody>
        <tr>
          <th>Num</th>
          <th>Source</th>
          <th>Destination</th>
          <th>Protocol</th>
          <th>Length</th>
          <th>Info</th>
        </tr>
        <tr v-for="(item, index) in destination">
          <td>{{ num[index] }}</td>
          <td>{{ source[index] }}</td>
          <td>{{ destination[index] }}</td>
          <td>{{ proto[index] }}</td>
          <td>{{ length[index] }}</td>
          <td>{{ info[index] }}</td>  
        </tr>
      </tbody>
    </table>
  </span>
</template>